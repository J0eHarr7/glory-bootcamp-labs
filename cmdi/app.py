import re
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)

HOME = """<!doctype html><html><head><title>Command Injection Lab</title>
<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9;max-width:700px;margin:40px auto}
a{color:#58a6ff}</style></head>
<body><h1>Command Injection Lab</h1>
<ul>
<li><a href="/level1">Level 1</a> — ping tool, no filtering (flag: /flag1.txt)</li>
<li><a href="/level2">Level 2</a> — ping tool, blocks ; & | &amp;&amp; || (flag: /flag2.txt)</li>
<li><a href="/level3">Level 3</a> — ping tool, blocks spaces and the above too (flag: /flag3.txt)</li>
</ul></body></html>"""


@app.route("/")
def home():
    return HOME


PAGE = """<!doctype html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9">
<h2>{{ title }}</h2>
<form>Host: <input name="host" size=50 value="{{ host }}"><button>Ping</button></form>
{% if note %}<p>{{ note }}</p>{% endif %}
{% if error %}<p style="color:#f85149">{{ error }}</p>{% endif %}
<pre style="border:1px solid #30363d;padding:10px;white-space:pre-wrap">{{ output }}</pre>
</body></html>"""


# ---------------- LEVEL 1: no filtering ----------------
@app.route("/level1")
def level1():
    host = request.args.get("host", "")
    output, error = "", None
    if host:
        try:
            # VULN: shell=True + string concatenation
            output = subprocess.run(f"ping -c 1 -W 1 {host}", shell=True,
                                     capture_output=True, text=True, timeout=5).stdout
        except Exception as e:
            error = str(e)
    return render_template_string(PAGE, title="Ping Tool (no filter)", host=host,
                                   note=None, error=error, output=output)


# ---------------- LEVEL 2: blocks shell metacharacters ----------------
BLOCKED_L2 = [";", "&", "|", "`", "$("]

@app.route("/level2")
def level2():
    host = request.args.get("host", "")
    output, error, note = "", None, "Blocked characters: ; & | ` $("
    if host:
        if any(ch in host for ch in BLOCKED_L2):
            error = "Blocked character detected."
        else:
            try:
                output = subprocess.run(f"ping -c 1 -W 1 {host}", shell=True,
                                         capture_output=True, text=True, timeout=5).stdout
            except Exception as e:
                error = str(e)
    return render_template_string(PAGE, title="Ping Tool (blacklist filter)", host=host,
                                   note=note, error=error, output=output)


# ---------------- LEVEL 3: blocks metacharacters AND whitespace ----------------
BLOCKED_L3 = [";", "&", "|", "`", "$(", " ", "\t"]

@app.route("/level3")
def level3():
    host = request.args.get("host", "")
    output, error, note = "", None, "Blocked: ; & | ` $( and whitespace (space/tab)"
    if host:
        if any(ch in host for ch in BLOCKED_L3):
            error = "Blocked character detected."
        else:
            try:
                output = subprocess.run(f"ping -c 1 -W 1 {host}", shell=True,
                                         capture_output=True, text=True, timeout=5).stdout
            except Exception as e:
                error = str(e)
    return render_template_string(PAGE, title="Ping Tool (strict filter)", host=host,
                                   note=note, error=error, output=output)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
