from flask import Flask, request, Response
import requests
import time

app = Flask(__name__)

WAF_UPSTREAM = "http://nginx:80"  # 'waf' = service name in docker-compose

# ---- simple header normalizer ---- #
def normalize_headers(headers):
    new_headers = {}

    for k, v in headers.items():
        key = k.strip().lower()

        # Normalize Content-Type value
        if key == "content-type":
            v = v.lower().replace(" ", "")

        # Drop any client-supplied x-forwarded-for
        if key == "x-forwarded-for":
            continue

        new_headers[key] = v

    return new_headers


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def proxy(path):
    # Build upstream URL (include query string)
    upstream_url = f"{WAF_UPSTREAM}/{path}"
    if request.query_string:
        upstream_url += "?" + request.query_string.decode("utf-8", errors="ignore")

    # Normalize headers
    headers = normalize_headers(dict(request.headers))

    # Read body
    body = request.get_data()

    # Simple timing for latency measurement
    start = time.time()
    upstream_resp = requests.request(
        method=request.method,
        url=upstream_url,
        headers=headers,
        data=body,
        allow_redirects=False,
    )
    elapsed = (time.time() - start) * 1000.0  # ms

    # Very simple logging for your report
    app.logger.info(
        f"{request.method} {request.path} -> {upstream_resp.status_code} in {elapsed:.2f} ms"
    )

    # Build response back to client
    # Optionally, you can strip hop-by-hop headers here if needed.
    resp_headers = [
        (k, v) for k, v in upstream_resp.headers.items()
    ]

    return Response(upstream_resp.content, upstream_resp.status_code, resp_headers)


if __name__ == "__main__":
    # Flask dev server, fine for this internal research proxy
    app.run(host="0.0.0.0", port=8081)






