import os
import re
import html
import secrets
from flask import Flask, request, render_template_string, jsonify

app = Flask(__name__)

FLAG_BLIND = os.environ.get("FLAG_BLIND", "CTF{xss_bl1nd_4dm1n_c00k13_st0l3n}")
ADMIN_SESSION_TOKEN = os.environ.get("ADMIN_SESSION_TOKEN", "s3cr3t-admin-session-" + secrets.token_hex(4))

feedback_store = []   # list of dicts: {id, name, message}
collected = []        # out-of-band exfil log

HOME = """<!doctype html><html><head><title>XSS Lab</title>
<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9;max-width:760px;margin:40px auto}
a{color:#58a6ff}code{background:#161b22;padding:2px 6px;border-radius:4px}</style></head>
<body><h1>XSS Lab — Reflected / DOM / Blind</h1>
<h3>Reflected</h3>
<ul>
<li><a href="/reflected/level1?q=test">Level 1</a> — raw HTML body context</li>
<li><a href="/reflected/level2?name=test">Level 2</a> — HTML attribute context, &lt;&gt; stripped</li>
<li><a href="/reflected/level3?term=test">Level 3</a> — inline &lt;script&gt; string context, quotes escaped</li>
</ul>
<h3>DOM-based (runs entirely in your browser, view-source to see the sink)</h3>
<ul>
<li><a href="/dom/level1#hello">Level 1</a> — innerHTML sink reading location.hash</li>
<li><a href="/dom/level2?cfg=1%2B1">Level 2</a> — eval() sink reading a query param</li>
</ul>
<h3>Blind</h3>
<ul>
<li><a href="/blind">Feedback form</a> — submissions are later opened by an admin bot</li>
<li><a href="/collected">Collected exfil</a> — what the bot leaked, if anything</li>
</ul>
</body></html>"""


@app.route("/")
def home():
    return HOME


# ============== REFLECTED XSS ==============

# Level 1: no encoding at all, raw HTML body context
LEVEL1 = """<!doctype html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9">
<h2>Search</h2>
<form>Query: <input name="q" value="{{ q_raw }}"><button>Go</button></form>
<p>You searched for: {{ q_echo|safe }}</p>
</body></html>"""

@app.route("/reflected/level1")
def reflected1():
    q = request.args.get("q", "")
    # VULN: q is embedded with |safe, completely unescaped
    return render_template_string(LEVEL1, q_raw=html.escape(q), q_echo=q)


# Level 2: attribute context; < and > are stripped, but quotes are not
def strip_angle_brackets(s):
    return s.replace("<", "").replace(">", "")

LEVEL2 = """<!doctype html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9">
<h2>Profile Name Preview</h2>
<form>Name: <input name="name" value="{{ name_raw }}"><button>Preview</button></form>
<p>Filter strips &lt; and &gt; only (not quotes, not other characters).</p>
<div id="preview" data-name="{{ name_filtered|safe }}">Preview badge</div>
</body></html>"""

@app.route("/reflected/level2")
def reflected2():
    name = request.args.get("name", "")
    filtered = strip_angle_brackets(name)
    return render_template_string(LEVEL2, name_raw=html.escape(name), name_filtered=filtered)


# Level 3: inline <script> string context; only double-quotes are backslash-escaped
def escape_quotes_only(s):
    return s.replace('"', '\\"')

LEVEL3 = """<!doctype html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9">
<h2>Live Search Widget</h2>
<form>Term: <input name="term" value="{{ term_raw }}"><button>Go</button></form>
<p>Filter escapes double-quotes with a backslash before placing the value into a JS string.</p>
<script>
  var lastSearch = "{{ term_js|safe }}";
  document.title = "Search: " + lastSearch;
</script>
<p>Open your browser console / view-source to see the generated script.</p>
</body></html>"""

@app.route("/reflected/level3")
def reflected3():
    term = request.args.get("term", "")
    js_safe = escape_quotes_only(term)
    return render_template_string(LEVEL3, term_raw=html.escape(term), term_js=js_safe)


# ============== DOM-BASED XSS ==============

DOM1 = """<!doctype html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9">
<h2>Welcome Banner (DOM XSS, innerHTML sink)</h2>
<div id="banner"></div>
<script>
  // VULN: untrusted location.hash written straight into innerHTML
  var name = decodeURIComponent(location.hash.slice(1)) || "guest";
  document.getElementById("banner").innerHTML = "Welcome, " + name + "!";
</script>
<p>Try changing the URL fragment after the #.</p>
</body></html>"""

@app.route("/dom/level1")
def dom1():
    return DOM1


DOM2 = """<!doctype html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9">
<h2>Inline Calculator (DOM XSS, eval sink)</h2>
<div id="result"></div>
<script>
  // VULN: a query-string "cfg" expression is eval'd client-side
  var params = new URLSearchParams(location.search);
  var expr = params.get("cfg") || "1+1";
  try {
    document.getElementById("result").textContent = "Result: " + eval(expr);
  } catch (e) {
    document.getElementById("result").textContent = "Error: " + e;
  }
</script>
</body></html>"""

@app.route("/dom/level2")
def dom2():
    return DOM2


# ============== BLIND XSS ==============

BLIND_FORM = """<!doctype html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9;max-width:700px;margin:40px auto">
<h2>Contact / Feedback</h2>
<p>Submitted messages are reviewed by an admin shortly after. You will not see the result here.</p>
<form method="POST">
Name: <input name="name" size=40><br><br>
Message:<br><textarea name="message" rows=5 style="width:100%"></textarea><br><br>
<button>Submit</button>
</form>
{% if submitted %}<p style="color:#3fb950">Thanks, your message was submitted.</p>{% endif %}
</body></html>"""

@app.route("/blind", methods=["GET", "POST"])
def blind():
    submitted = False
    if request.method == "POST":
        name = request.form.get("name", "anonymous")[:200]
        message = request.form.get("message", "")[:2000]
        feedback_store.append({"id": len(feedback_store) + 1, "name": name, "message": message})
        submitted = True
    return render_template_string(BLIND_FORM, submitted=submitted)


ADMIN_QUEUE = """<!doctype html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9">
<h2>Admin — Feedback Queue</h2>
{% for item in items %}
<div style="border:1px solid #30363d;padding:10px;margin-bottom:10px">
<b>From:</b> {{ item.name|safe }}<br>
<b>Message:</b> {{ item.message|safe }}
</div>
{% endfor %}
</body></html>"""

@app.route("/admin/queue")
def admin_queue():
    # VULN: stored feedback is rendered unescaped for the admin to review
    return render_template_string(ADMIN_QUEUE, items=feedback_store)


@app.route("/admin/secret")
def admin_secret():
    # Simulates an admin-only endpoint protected by a session cookie.
    if request.cookies.get("admin_session") != ADMIN_SESSION_TOKEN:
        return jsonify(error="forbidden"), 403
    return jsonify(flag=FLAG_BLIND)


@app.route("/collect")
def collect():
    data = request.args.get("data", "")
    collected.append(data)
    return "ok"


@app.route("/collected")
def collected_view():
    return jsonify(collected=collected)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
