from flask import Flask, request, jsonify
import time
import os
import json
import xml.etree.ElementTree as ET

app = Flask(__name__)

# --- Logging Configuration ---
# Get the absolute path of the directory this script is in
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
# Join it with "logs" to get an absolute, predictable path
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

def write_raw(req_body, headers):
    ts = int(time.time() * 1000)
    fname = f"{LOG_DIR}/raw_{ts}.log"
    # print(f"Writing log to {fname}") # Optional: Reduce noise
    try:
        with open(fname, "wb") as f:
            f.write(b"--- HEADERS ---\n")
            for k, v in headers.items():
                f.write(f"{k}: {v}\n".encode('utf-8', errors='ignore'))
            f.write(b"\n--- BODY ---\n")
            if isinstance(req_body, bytes):
                f.write(req_body)
            else:
                f.write(str(req_body).encode('utf-8', errors='ignore'))
    except Exception as e:
        print(f"Error writing log: {e}")

@app.route("/echo", methods=["POST", "GET"])
def echo():
    # 1. Capture Raw Data
    # We use get_data() to ensure we get bytes before Flask processes forms
    raw = request.get_data() or b""
    write_raw(raw, dict(request.headers))

    received_field = None

    # 2. Try Parsing as JSON
    # We try this even if Content-Type is wrong (to emulate "sniffing")
    if received_field is None:
        try:
            # silent=True returns None if parsing fails instead of raising 400
            json_body = request.get_json(silent=True, force=True) 
            if isinstance(json_body, dict):
                received_field = json_body.get("field")
        except Exception:
            pass

    # 3. Try Parsing as Form/Query Params (Regex Fallback)
    # This handles x-www-form-urlencoded or weirdly formatted bodies
    if received_field is None:
        try:
            txt = raw.decode('utf-8', errors='ignore')
            if 'field=' in txt:
                import urllib.parse
                # Simple check for field=value pattern
                for part in txt.replace('&', '\n').split(): 
                    if part.startswith('field='):
                        received_field = urllib.parse.unquote_plus(part.split('=', 1)[1])
                        break
        except Exception:
            pass

    # 4. NEW: Try Parsing as XML
    # This allows us to detect XXE bypasses
    if received_field is None and raw.strip().startswith(b'<'):
        try:
            # We use standard ElementTree. 
            # Note: This is vulnerable to "Billion Laughs" but robust against XXE 
            # unless specifically configured otherwise, but it confirms XML processing.
            root = ET.fromstring(raw)
            # Look for <field>text</field>
            field_elem = root.find('field')
            if field_elem is not None:
                received_field = field_elem.text
        except Exception:
            pass

    # 5. Return Response
    # We always return 200 OK to prove we processed the request.
    # If we crashed (500), that is also a finding (DoS).
    return jsonify({
        "received_field": received_field,
        "raw_len": len(raw),
        "status": "processed"
    }), 200

if __name__ == "__main__":
    # We bind to 0.0.0.0 so Docker can forward traffic to us
    app.run(host="0.0.0.0", port=5000)