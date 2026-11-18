import os
from flask import Flask, request

app = Flask(__name__, static_folder="static", static_url_path="/static")

FLAG1 = os.environ.get("FLAG1", "CTF{csti_l1_sc0p3_d4t4_l34k3d}")
FLAG2 = os.environ.get("FLAG2", "CTF{csti_l2_bl4ckl1st_byp4ss3d_br4ck3t}")

HOME = """<!doctype html><html><head><title>CSTI Lab</title>
<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9;max-width:700px;margin:40px auto}
a{color:#58a6ff}code{background:#161b22;padding:2px 6px;border-radius:4px}</style></head>
<body><h1>Client-Side Template Injection Lab (AngularJS 1.2.9)</h1>
<ul>
<li><a href="/level1">Level 1</a> — raw injection into an Angular-compiled page</li>
<li><a href="/level2">Level 2</a> — server-side word blacklist on "secretFlag"</li>
</ul>
<p>Both pages have a hidden <code>$scope.secretFlag</code> never rendered by the app itself.
Your review text is inserted directly into the page's HTML <i>before</i> Angular compiles it,
so an Angular expression in your input gets evaluated against that scope.</p>
</body></html>"""


@app.route("/")
def home():
    return HOME


# ---------------- LEVEL 1: raw injection ----------------
LEVEL1 = """<!doctype html><html ng-app="labApp">
<head><script src="/static/angular.min.js"></script>
<script>
angular.module('labApp', []).controller('MainCtrl', function($scope) {{
  $scope.secretFlag = {flag!r};
}});
</script></head>
<body ng-controller="MainCtrl" style="font-family:monospace;background:#0d1117;color:#c9d1d9;max-width:700px;margin:40px auto">
<h2>Product Review</h2>
<form>Review: <input name="review" size=50 value="{payload_attr}"><button>Submit</button></form>
<hr><p>Review: {payload}</p>
</body></html>"""

@app.route("/level1")
def level1():
    payload = request.args.get("review", "Nice product, fast shipping!")
    payload_attr = payload.replace('"', "&quot;")
    return LEVEL1.format(payload=payload, payload_attr=payload_attr, flag=FLAG1)


# ---------------- LEVEL 2: naive word blacklist ----------------
LEVEL2 = """<!doctype html><html ng-app="labApp">
<head><script src="/static/angular.min.js"></script>
<script>
angular.module('labApp', []).controller('MainCtrl', function($scope) {{
  $scope.secretFlag = {flag!r};
}});
</script></head>
<body ng-controller="MainCtrl" style="font-family:monospace;background:#0d1117;color:#c9d1d9;max-width:700px;margin:40px auto">
<h2>Product Review (filtered)</h2>
<p>Server blocks any review containing the word "secretFlag" (case-insensitive).</p>
<form>Review: <input name="review" size=50 value="{payload_attr}"><button>Submit</button></form>
<hr><p>Review: {payload}</p>
</body></html>"""

@app.route("/level2")
def level2():
    payload = request.args.get("review", "Nice product, fast shipping!")
    if "secretflag" in payload.lower():
        return "Blocked: that word is not allowed.", 400
    payload_attr = payload.replace('"', "&quot;")
    return LEVEL2.format(payload=payload, payload_attr=payload_attr, flag=FLAG2)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
