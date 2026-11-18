import os
import time
import threading
from flask import Flask, request, jsonify, session, render_template_string

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "race-lab-dev-key")

FLAG1 = os.environ.get("FLAG1", "CTF{r4c3_l1_c0up0n_r3d33m3d_mult1pl3_t1m3s}")
FLAG2 = os.environ.get("FLAG2", "CTF{r4c3_l2_n3g4t1v3_b4l4nc3_t0ct0u}")

wallets = {}          # username -> balance
coupon_redeemed = {}  # username -> count


def get_user():
    if "user" not in session:
        session["user"] = f"guest{os.urandom(4).hex()}"
    u = session["user"]
    wallets.setdefault(u, 100)
    coupon_redeemed.setdefault(u, 0)
    return u


HOME = """<!doctype html><html><head><title>Race Condition Lab</title>
<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9;max-width:760px;margin:40px auto}
a{color:#58a6ff}code{background:#161b22;padding:2px 6px;border-radius:4px}</style></head>
<body><h1>Race Condition Lab</h1>
<p>You are <b>{{ user }}</b>, wallet balance: <b>{{ balance }}</b> coins, coupon redeemed: <b>{{ redeemed }}</b> time(s).</p>
<ul>
<li><code>POST /level1/redeem</code> — one-time 50% discount coupon (check-then-act, no lock). Flag appears once redeemed 3+ times.</li>
<li><code>POST /level2/withdraw</code> body <code>{"amount": N}</code> — withdraw from wallet (TOCTOU on balance check). Flag appears once balance goes negative.</li>
<li><code>GET /reset</code> — reset your session state</li>
</ul>
<p>Fire many CONCURRENT requests (not sequential ones) to win the race. A single curl will just behave correctly.</p>
</body></html>"""


@app.route("/")
def home():
    u = get_user()
    return render_template_string(HOME, user=u, balance=wallets[u], redeemed=coupon_redeemed[u])


@app.route("/reset")
def reset():
    u = get_user()
    wallets[u] = 100
    coupon_redeemed[u] = 0
    return jsonify(message="reset", balance=wallets[u], redeemed=coupon_redeemed[u])


# ---------------- LEVEL 1: coupon redeemed multiple times ----------------
@app.route("/level1/redeem", methods=["POST"])
def level1_redeem():
    u = get_user()
    # VULN: check-then-act with an artificial delay between check and write,
    # and NO lock around the critical section -> classic TOCTOU race.
    if coupon_redeemed[u] >= 1:
        return jsonify(error="Coupon already redeemed", redeemed=coupon_redeemed[u]), 400
    time.sleep(0.25)  # simulates a slow downstream call (e.g. payment provider)
    coupon_redeemed[u] += 1
    wallets[u] += 50
    flag = FLAG1 if coupon_redeemed[u] >= 3 else None
    return jsonify(message="Coupon redeemed", redeemed=coupon_redeemed[u], balance=wallets[u], flag=flag)


# ---------------- LEVEL 2: withdraw past zero via TOCTOU ----------------
@app.route("/level2/withdraw", methods=["POST"])
def level2_withdraw():
    u = get_user()
    body = request.get_json(silent=True) or {}
    try:
        amount = float(body.get("amount", 0))
    except (TypeError, ValueError):
        return jsonify(error="bad amount"), 400
    if amount <= 0:
        return jsonify(error="amount must be positive"), 400

    current = wallets[u]
    if amount > current:
        return jsonify(error="insufficient funds", balance=current), 400
    time.sleep(0.2)  # VULN: check happened against a stale balance; the live
                      # balance is still decremented here with no lock in between
    wallets[u] -= amount
    flag = FLAG2 if wallets[u] < 0 else None
    return jsonify(message="withdrawn", balance=wallets[u], flag=flag)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
