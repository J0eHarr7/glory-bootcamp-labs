import os
import sqlite3
import time
from flask import Flask, request, render_template_string, g

app = Flask(__name__)
DB_PATH = os.environ.get("DB_PATH", "/tmp/shop.db")

FLAG_UNION = os.environ.get("FLAG_UNION", "CTF{un10n_b4s3d_sql1_3xf1ltr4t10n}")
FLAG_BOOL = os.environ.get("FLAG_BOOL", "CTF{bool34n_bl1nd_sql1_tru3_f4ls3}")
FLAG_TIME = os.environ.get("FLAG_TIME", "CTF{t1m3_b4s3d_bl1nd_sql1_sl33p}")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.create_function("SLEEP", 1, lambda n: (time.sleep(float(n)), 0)[1])
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
    DROP TABLE IF EXISTS products;
    DROP TABLE IF EXISTS users;
    DROP TABLE IF EXISTS secrets;
    DROP TABLE IF EXISTS flag_time;
    CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL, category TEXT);
    CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, is_admin INTEGER);
    CREATE TABLE secrets (id INTEGER PRIMARY KEY, flag TEXT);
    CREATE TABLE flag_time (id INTEGER PRIMARY KEY, value TEXT);
    """)
    conn.executemany("INSERT INTO products (name, price, category) VALUES (?,?,?)", [
        ("Mechanical Keyboard", 79.99, "electronics"),
        ("USB-C Hub", 24.99, "electronics"),
        ("Coffee Mug", 9.99, "kitchen"),
        ("Notebook", 3.50, "office"),
        ("Desk Lamp", 19.99, "office"),
    ])
    conn.execute("INSERT INTO users (username, password, is_admin) VALUES (?,?,?)", ("admin", FLAG_BOOL, 1))
    conn.executemany("INSERT INTO users (username, password, is_admin) VALUES (?,?,?)", [
        ("alice", "alice123", 0),
        ("bob", "bob123", 0),
    ])
    conn.execute("INSERT INTO secrets (flag) VALUES (?)", (FLAG_UNION,))
    conn.execute("INSERT INTO flag_time (value) VALUES (?)", (FLAG_TIME,))
    conn.commit()
    conn.close()


HOME = """<!doctype html><html><head><title>SQLi Lab</title>
<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9;max-width:700px;margin:40px auto}
a{color:#58a6ff}</style></head>
<body><h1>SQL Injection Lab (SQLite)</h1>
<ul>
<li><a href="/level1">Level 1</a> — product search, UNION-based (hidden "secrets" table)</li>
<li><a href="/level2">Level 2</a> — username check, boolean-based blind (flag is admin's password)</li>
<li><a href="/level3">Level 3</a> — product lookup, time-based blind (no visible output at all)</li>
</ul></body></html>"""


@app.route("/")
def home():
    return HOME


# ---------------- LEVEL 1: UNION-based ----------------
LEVEL1 = """<!doctype html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9">
<h2>Product Search</h2>
<form>Search: <input name="q" size=50 value="{{ q }}"><button>Search</button></form>
<p>Query returns 4 columns: id, name, price, category</p>
{% if error %}<p style="color:#f85149">{{ error }}</p>{% endif %}
<table border=1 cellpadding=6>
<tr><th>ID</th><th>Name</th><th>Price</th><th>Category</th></tr>
{% for row in rows %}<tr>{% for c in row %}<td>{{ c }}</td>{% endfor %}</tr>{% endfor %}
</table>
</body></html>"""

@app.route("/level1")
def level1():
    q = request.args.get("q", "")
    db = get_db()
    sql = f"SELECT id, name, price, category FROM products WHERE name LIKE '%{q}%'"
    rows, error = [], None
    try:
        rows = db.execute(sql).fetchall()
    except Exception as e:
        error = f"DB error: {e}"
    return render_template_string(LEVEL1, q=q, rows=rows, error=error)


# ---------------- LEVEL 2: boolean-based blind ----------------
LEVEL2 = """<!doctype html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9">
<h2>Username Availability Check</h2>
<form>Username: <input name="username" size=50 value="{{ u }}"><button>Check</button></form>
<p>No data is ever shown back - only "exists" or "not found".</p>
<hr><p>Status: <b style="color:{{ color }}">{{ status }}</b></p>
{% if error %}<p style="color:#f85149">{{ error }}</p>{% endif %}
</body></html>"""

@app.route("/level2")
def level2():
    u = request.args.get("username", "")
    if not u:
        return render_template_string(LEVEL2, u="", status="Enter a username", color="#8b949e", error=None)
    db = get_db()
    sql = f"SELECT id FROM users WHERE username = '{u}'"
    status, color, error = "User not found", "#f85149", None
    try:
        row = db.execute(sql).fetchone()
        if row:
            status, color = "User exists", "#3fb950"
    except Exception as e:
        error = f"DB error: {e}"
    return render_template_string(LEVEL2, u=u, status=status, color=color, error=error)


# ---------------- LEVEL 3: time-based blind ----------------
LEVEL3 = """<!doctype html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9">
<h2>Product Lookup (silent endpoint)</h2>
<form>Product ID: <input name="id" value="{{ pid }}"><button>Lookup</button></form>
<p>Response text never changes, whatever you send, true or false, error or not.</p>
<hr><p>{{ msg }}</p>
</body></html>"""

@app.route("/level3")
def level3():
    pid = request.args.get("id", "")
    db = get_db()
    msg = "Request processed."
    if pid.strip():
        sql = f"SELECT id FROM products WHERE id = {pid}"
        try:
            db.execute(sql).fetchall()
        except Exception:
            pass
    return render_template_string(LEVEL3, pid=pid, msg=msg)


with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
