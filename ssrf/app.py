import os
import requests
from flask import Flask, request, render_template_string, jsonify

app = Flask(__name__)

INTERNAL_BASE = os.environ.get("INTERNAL_BASE", "http://internal-service:8000")
FLAG_ADMIN = os.environ.get("FLAG_ADMIN", "J0eHarr7{ssrf_l2_l00pb4ck_3nc0d1ng_byp4ss}")

HOME = """<!doctype html><html><head><title>SSRF Lab</title>
<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9;max-width:760px;margin:40px auto}
a{color:#58a6ff}code{background:#161b22;padding:2px 6px;border-radius:4px}</style></head>
<body><h1>Server-Side Request Forgery Lab</h1>
<ul>
<li><a href="/level1">Level 1</a> — image proxy, no validation at all</li>
<li><a href="/level2">Level 2</a> — blocks literal "127.0.0.1" / "localhost" / "169.254"</li>
<li><a href="/level3">Level 3</a> — allowlist requires URL to start with an approved host</li>
</ul>
</body></html>"""


@app.route("/")
def home():
    return HOME


PAGE = """<!doctype html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9;max-width:800px;margin:20px auto">
<h2>{title}</h2>
<form>URL: <input name="url" size=70 value="{url_attr}"><button>Fetch</button></form>
<p>{note}</p>
{error}
<pre style="border:1px solid #30363d;padding:10px;white-space:pre-wrap">{body}</pre>
</body></html>"""


def do_fetch(url):
    r = requests.get(url, timeout=4)
    return r.text[:4000]


# ---------------- LEVEL 1: no validation ----------------
@app.route("/level1")
def level1():
    url = request.args.get("url", "")
    body, error = "", ""
    if url:
        try:
            body = do_fetch(url)
        except Exception as e:
            error = f'<p style="color:#f85149">Fetch error: {e}</p>'
    return PAGE.format(title="Image/Webhook Fetcher (no filter)",
                        url_attr=url.replace('"', "&quot;"),
                        note="Fetches any URL you give it and shows the response body.",
                        error=error, body=body)


# ---------------- LEVEL 2: naive loopback blacklist ----------------
BLOCKED_L2 = ["127.0.0.1", "localhost", "169.254", "internal-service"]

@app.route("/internal/admin")
def internal_admin():
    # Only meant to be reachable from the app's own loopback - classic
    # "trust requests from localhost" pattern, exactly what SSRF abuses.
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return jsonify(error="forbidden: admin panel is localhost-only"), 403
    return jsonify(message="Welcome, local admin", flag=FLAG_ADMIN)

@app.route("/level2")
def level2():
    url = request.args.get("url", "")
    body, error = "", ""
    if url:
        if any(b in url.lower() for b in BLOCKED_L2):
            error = '<p style="color:#f85149">Blocked: URL contains a disallowed host.</p>'
        else:
            try:
                body = do_fetch(url)
            except Exception as e:
                error = f'<p style="color:#f85149">Fetch error: {e}</p>'
    return PAGE.format(title="Image/Webhook Fetcher (loopback blacklist)",
                        url_attr=url.replace('"', "&quot;"),
                        note=f"Blocked substrings: {BLOCKED_L2}",
                        error=error, body=body)


# ---------------- LEVEL 3: allowlist checked with a naive prefix match ----------------
ALLOWED_PREFIX = "http://public-api.lab.local"  # VULN: missing boundary check after the host

@app.route("/level3")
def level3():
    url = request.args.get("url", "")
    body, error = "", ""
    if url:
        if not url.lower().startswith(ALLOWED_PREFIX):
            error = f'<p style="color:#f85149">Blocked: URL must start with {ALLOWED_PREFIX}</p>'
        else:
            try:
                body = do_fetch(url)
            except Exception as e:
                error = f'<p style="color:#f85149">Fetch error: {e}</p>'
    return PAGE.format(title="Image/Webhook Fetcher (allowlist)",
                        url_attr=url.replace('"', "&quot;"),
                        note=f"Only URLs starting with {ALLOWED_PREFIX} are allowed.",
                        error=error, body=body)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
