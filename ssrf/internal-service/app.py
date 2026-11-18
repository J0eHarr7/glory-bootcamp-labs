import os
from flask import Flask, jsonify

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "J0eHarr7{ssrf_1nt3rn4l_m3t4d4t4_r34ch3d}")

# Simulates a cloud instance metadata endpoint (AWS-style) that should
# never be reachable from the public internet, only from the app server
# itself - which is exactly the SSRF primitive this lab demonstrates.
@app.route("/latest/meta-data/")
def meta_root():
    return "ami-id\nhostname\niam/\nflag\n", 200, {"Content-Type": "text/plain"}

@app.route("/latest/meta-data/flag")
def meta_flag():
    return FLAG, 200, {"Content-Type": "text/plain"}

@app.route("/latest/meta-data/iam/security-credentials/admin")
def meta_creds():
    return jsonify(AccessKeyId="AKIA_FAKE_DEMO", SecretAccessKey="not-a-real-secret", Token=FLAG)

@app.route("/")
def home():
    return "internal metadata service - not meant to be reached from outside"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
