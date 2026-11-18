import os
from flask import Flask, request, render_template_string

app = Flask(__name__)

HOME = """<!doctype html><html><head><title>SSTI Lab</title>
<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9;max-width:700px;margin:40px auto}
a{color:#58a6ff}code{background:#161b22;padding:2px 6px;border-radius:4px}</style></head>
<body><h1>SSTI Lab (Jinja2 / Flask)</h1>
<p>Each level writes its flag to a file only readable via real RCE achieved through the injection.</p>
<ul>
<li><a href="/level1">Level 1</a> — raw injection, greeting card generator (flag: /flag1.txt)</li>
<li><a href="/level2">Level 2</a> — naive word blacklist (flag: /flag2.txt)</li>
<li><a href="/level3">Level 3</a> — stricter filter, requires an alternate gadget (flag: /flag3.txt)</li>
</ul></body></html>"""


@app.route("/")
def home():
    return HOME


# ---------------- LEVEL 1: raw injection ----------------
LEVEL1 = """<!doctype html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9">
<h2>Greeting Card Generator</h2>
<form>Name: <input name="name" value="{{ request.args.get('name','') }}"><button>Go</button></form>
<hr><p>Card says:</p><div style="border:1px solid #30363d;padding:10px">{{ card|safe }}</div>
</body></html>"""

@app.route("/level1")
def level1():
    name = request.args.get("name", "World")
    # VULN: f-string builds the template itself out of user input
    rendered_card = render_template_string(f"Hello, {name}! Welcome to SSTI Lab.")
    return render_template_string(LEVEL1, card=rendered_card)


# ---------------- LEVEL 2: naive blacklist ----------------
BLACKLIST_L2 = ["config", "os", "import", "popen", "subprocess", "system"]

LEVEL2 = """<!doctype html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9">
<h2>Bio Template Preview (filtered)</h2>
<form>Bio: <input name="bio" size=60 value="{{ request.args.get('bio','') }}"><button>Preview</button></form>
<p>Blocked words: {{ blacklist }}</p>
<hr>{% if error %}<p style="color:#f85149">{{ error }}</p>{% else %}
<div style="border:1px solid #30363d;padding:10px">{{ bio_html|safe }}</div>{% endif %}
</body></html>"""

@app.route("/level2")
def level2():
    bio = request.args.get("bio", "")
    for bad in BLACKLIST_L2:
        if bad in bio.lower():
            return render_template_string(LEVEL2, error=f"Blocked word detected: '{bad}'",
                                           blacklist=BLACKLIST_L2, bio_html="")
    try:
        bio_html = render_template_string(bio)
    except Exception as e:
        bio_html = f"Template error: {e}"
    return render_template_string(LEVEL2, error=None, blacklist=BLACKLIST_L2, bio_html=bio_html)


# ---------------- LEVEL 3: stricter filter ----------------
def level3_blocked(s: str) -> bool:
    s_low = s.lower()
    banned_words = ["config", "os", "import", "popen", "subprocess", "system", "class", "mro", "base", "global"]
    if any(b in s_low for b in banned_words):
        return True
    if "__" in s:          # blocks literal dunder
        return True
    return False

LEVEL3 = """<!doctype html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9">
<h2>Feedback Formatter (strict filter)</h2>
<form>Feedback: <input name="msg" size=70 value="{{ request.args.get('msg','') }}"><button>Format</button></form>
<p>Filter blocks: class / mro / base / global / os / config / import / subprocess / popen / system / literal "__"</p>
<hr>{% if error %}<p style="color:#f85149">{{ error }}</p>{% else %}
<div style="border:1px solid #30363d;padding:10px">{{ out|safe }}</div>{% endif %}
</body></html>"""

@app.route("/level3")
def level3():
    msg = request.args.get("msg", "")
    if level3_blocked(msg):
        return render_template_string(LEVEL3, error="Blocked by filter.", out="")
    try:
        out = render_template_string(msg)
    except Exception as e:
        out = f"Template error: {e}"
    return render_template_string(LEVEL3, error=None, out=out)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
