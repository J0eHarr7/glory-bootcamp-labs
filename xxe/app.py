import os
from flask import Flask, request, render_template_string
from lxml import etree

app = Flask(__name__)

HOME = """<!doctype html><html><head><title>XML Injection / XXE Lab</title>
<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9;max-width:700px;margin:40px auto}
a{color:#58a6ff}code{background:#161b22;padding:2px 6px;border-radius:4px}</style></head>
<body><h1>XML Injection / XXE Lab</h1>
<ul>
<li><a href="/level1">Level 1</a> — in-band XXE: result is reflected (flag: /flag1.txt)</li>
<li><a href="/level2">Level 2</a> — blind / out-of-band XXE: nothing is reflected (flag: /flag2.txt)</li>
</ul>
<p>Both levels accept raw XML via a textarea POST to the same page.</p>
</body></html>"""


@app.route("/")
def home():
    return HOME


# ---------------- LEVEL 1: classic in-band XXE ----------------
LEVEL1 = """<!doctype html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9;max-width:800px;margin:20px auto">
<h2>Product Review Importer (reflects parsed content)</h2>
<form method="POST">
<textarea name="xml" rows=10 style="width:100%">{{ xml_in }}</textarea><br><button>Import</button>
</form>
<p>The &lt;review&gt; element's text is echoed back below.</p>
{% if error %}<p style="color:#f85149">{{ error }}</p>{% endif %}
<pre style="border:1px solid #30363d;padding:10px;white-space:pre-wrap">{{ result }}</pre>
</body></html>"""

DEFAULT_XML_L1 = """<?xml version="1.0"?>
<review>
  <product>Mechanical Keyboard</product>
  <rating>5</rating>
  <comment>Great build quality!</comment>
</review>"""

@app.route("/level1", methods=["GET", "POST"])
def level1():
    xml_in = request.form.get("xml", DEFAULT_XML_L1)
    result, error = "", None
    if request.method == "POST":
        try:
            # VULN: resolve_entities + load_dtd + no_network=False allows external entities
            parser = etree.XMLParser(resolve_entities=True, no_network=False, load_dtd=True)
            tree = etree.fromstring(xml_in.encode(), parser=parser)
            comment = tree.findtext("comment") or "(no comment field)"
            product = tree.findtext("product") or "?"
            rating = tree.findtext("rating") or "?"
            result = f"Product: {product}\nRating: {rating}\nComment: {comment}"
        except Exception as e:
            error = f"XML parse error: {e}"
    return render_template_string(LEVEL1, xml_in=xml_in, result=result, error=error)


# ---------------- LEVEL 2: blind / out-of-band XXE ----------------
LEVEL2 = """<!doctype html><html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9;max-width:800px;margin:20px auto">
<h2>Invoice Processor (no output at all)</h2>
<form method="POST">
<textarea name="xml" rows=10 style="width:100%">{{ xml_in }}</textarea><br><button>Process</button>
</form>
<p>Response is always "Processed." regardless of content or parse errors. No data is ever reflected.</p>
<p>Hint: use an external DTD hosted on a server you control to exfiltrate data out-of-band.</p>
<hr><p>{{ result }}</p>
</body></html>"""

DEFAULT_XML_L2 = """<?xml version="1.0"?>
<invoice>
  <item>USB-C Hub</item>
  <amount>24.99</amount>
</invoice>"""

@app.route("/level2", methods=["GET", "POST"])
def level2():
    xml_in = request.form.get("xml", DEFAULT_XML_L2)
    if request.method == "POST":
        try:
            parser = etree.XMLParser(resolve_entities=True, no_network=False, load_dtd=True, dtd_validation=True)
            etree.fromstring(xml_in.encode(), parser=parser)
        except Exception:
            pass  # deliberately silent: no error shown, no boolean oracle
    return render_template_string(LEVEL2, xml_in=xml_in, result="Processed.")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
