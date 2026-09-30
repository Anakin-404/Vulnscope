import os

from flask import Flask, render_template_string, request

from database import get_history, init_db, save_scan
from nvd_client import NVDClient

app = Flask(__name__)
application = app
handler = app
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")
init_db()

HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>VulnScope</title>
  <style>
    :root {
      --bg: #0b1220;
      --panel: #111827;
      --panel-alt: #1f2937;
      --line: #2b3a4f;
      --text: #e5e7eb;
      --muted: #9ca3af;
      --accent: #60a5fa;
      --danger: #ef4444;
      --success: #22c55e;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    .container {
      max-width: 1100px;
      margin: 0 auto;
      padding: 2rem 1rem 4rem;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 12px;
      box-shadow: 0 8px 28px rgba(0,0,0,0.25);
      padding: 1.25rem;
      margin-top: 1rem;
    }
    .form-grid {
      display: grid;
      grid-template-columns: 2fr 1fr 1fr auto;
      gap: 0.75rem;
      align-items: end;
    }
    label {
      display: block;
      font-size: 0.85rem;
      color: var(--muted);
      margin-bottom: 0.35rem;
    }
    input, button, select {
      width: 100%;
      border-radius: 10px;
      border: 1px solid var(--line);
      background: #0f172a;
      color: var(--text);
      padding: 0.8rem 0.9rem;
      font-size: 1rem;
    }
    button {
      background: var(--accent);
      color: #08111f;
      font-weight: 700;
      cursor: pointer;
    }
    .dashboard {
      display: grid;
      grid-template-columns: repeat(5, minmax(110px, 1fr));
      gap: 0.75rem;
      margin-top: 1rem;
    }
    .metric {
      padding: 1rem;
      background: var(--panel-alt);
      border: 1px solid var(--line);
      border-radius: 10px;
    }
    .metric .label {
      display: block;
      font-size: 0.8rem;
      color: var(--muted);
      margin-bottom: 0.35rem;
    }
    .metric .value {
      font-size: 1.8rem;
      font-weight: 700;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 0.75rem;
    }
    th, td {
      text-align: left;
      padding: 0.75rem 0.5rem;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
    }
    th {
      color: var(--muted);
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }
    .muted { color: var(--muted); }
    .error { color: var(--danger); }
    .success { color: var(--success); }
    .small { font-size: 0.85rem; }
    .pill {
      display: inline-block;
      padding: 0.25rem 0.5rem;
      border-radius: 999px;
      background: rgba(96, 165, 250, 0.12);
      border: 1px solid rgba(96, 165, 250, 0.4);
      color: var(--text);
      font-size: 0.8rem;
    }
    @media (max-width: 820px) {
      .form-grid, .dashboard { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ VulnScope</h1>
    <p class="muted">Software Vulnerability Discovery & Analysis Tool</p>

    <div class="card">
      <form method="post" action="/scan">
        <div class="form-grid">
          <div>
            <label for="product">Software / Product</label>
            <input id="product" name="product" placeholder="e.g. Google Chrome" value="{{ product or '' }}" required />
          </div>
          <div>
            <label for="version">Version</label>
            <input id="version" name="version" placeholder="e.g. 120.0" value="{{ version or '' }}" required />
          </div>
          <div>
            <label for="api_key">NVD API Key (optional)</label>
            <input id="api_key" name="api_key" type="password" placeholder="Optional" />
          </div>
          <div>
            <button type="submit">Scan</button>
          </div>
        </div>
      </form>
    </div>

    {% if error %}
      <div class="card error">{{ error }}</div>
    {% endif %}

    {% if results %}
      {% set all_cves = [] %}
      {% for item in results %}
        {% for cve in item.cves %}
          {% set _ = all_cves.append(cve) %}
        {% endfor %}
      {% endfor %}
      {% set critical = 0 %}
      {% set high = 0 %}
      {% set medium = 0 %}
      {% set low = 0 %}
      {% for cve in all_cves %}
        {% if cve.severity == 'CRITICAL' %}{% set critical = critical + 1 %}{% endif %}
        {% if cve.severity == 'HIGH' %}{% set high = high + 1 %}{% endif %}
        {% if cve.severity == 'MEDIUM' %}{% set medium = medium + 1 %}{% endif %}
        {% if cve.severity == 'LOW' %}{% set low = low + 1 %}{% endif %}
      {% endfor %}

      <div class="card">
        <h2>Security Overview</h2>
        <div class="dashboard">
          <div class="metric"><span class="label">Software Scanned</span><span class="value">{{ results|length }}</span></div>
          <div class="metric"><span class="label">CVEs Found</span><span class="value">{{ all_cves|length }}</span></div>
          <div class="metric"><span class="label">Critical</span><span class="value">{{ critical }}</span></div>
          <div class="metric"><span class="label">High</span><span class="value">{{ high }}</span></div>
          <div class="metric"><span class="label">Medium / Low</span><span class="value">{{ medium + low }}</span></div>
        </div>
      </div>

      <div class="card">
        <h2>Vulnerability Summary</h2>
        <table>
          <thead>
            <tr>
              <th>Software</th>
              <th>Version</th>
              <th>CVEs Found</th>
              <th>Highest Severity</th>
            </tr>
          </thead>
          <tbody>
            {% for item in results %}
              {% set rank = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0} %}
              {% set highest = '—' %}
              {% if item.cves %}
                {% set highest = item.cves[0].severity %}
                {% for cve in item.cves[1:] %}
                  {% if rank.get(cve.severity, 0) > rank.get(highest, 0) %}
                    {% set highest = cve.severity %}
                  {% endif %}
                {% endfor %}
              {% endif %}
              <tr>
                <td>{{ item.product }}</td>
                <td>{{ item.version }}</td>
                <td>{{ item.cves|length }}</td>
                <td><span class="pill">{{ highest }}</span></td>
              </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>

      <div class="card">
        <h2>CVE Details</h2>
        <table>
          <thead>
            <tr>
              <th>Software</th>
              <th>Version</th>
              <th>CVE</th>
              <th>Severity</th>
              <th>CVSS</th>
              <th>Published</th>
            </tr>
          </thead>
          <tbody>
            {% for item in results %}
              {% for cve in item.cves %}
                <tr>
                  <td>{{ item.product }}</td>
                  <td>{{ item.version }}</td>
                  <td>{{ cve.id }}</td>
                  <td>{{ cve.severity }}</td>
                  <td>{{ cve.cvss }}</td>
                  <td>{{ cve.published }}</td>
                </tr>
              {% endfor %}
            {% endfor %}
          </tbody>
        </table>
      </div>
    {% endif %}

    <div class="card">
      <h2>Scan History</h2>
      {% if history %}
        <table>
          <thead>
            <tr>
              <th>Scanned At</th>
              <th>Software</th>
              <th>Version</th>
              <th>CVEs</th>
              <th>Highest Severity</th>
            </tr>
          </thead>
          <tbody>
            {% for row in history %}
              <tr>
                <td>{{ row['Scanned At'] }}</td>
                <td>{{ row['Software'] }}</td>
                <td>{{ row['Version'] }}</td>
                <td>{{ row['CVEs'] }}</td>
                <td>{{ row['Highest Severity'] }}</td>
              </tr>
            {% endfor %}
          </tbody>
        </table>
      {% else %}
        <p class="muted">No previous scans yet.</p>
      {% endif %}
    </div>
  </div>
</body>
</html>
"""


@app.get("/")
def home():
    return render_template_string(HTML_TEMPLATE, results=[], history=get_history(limit=10), product="", version="", error="")


@app.post("/scan")
def scan():
    product = (request.form.get("product") or "").strip()
    version = (request.form.get("version") or "").strip()
    api_key = (request.form.get("api_key") or "").strip() or None

    if not product or not version:
        return render_template_string(
            HTML_TEMPLATE,
            results=[],
            history=get_history(limit=10),
            product=product,
            version=version,
            error="Enter both product and version.",
        )

    client = NVDClient(api_key=api_key)
    results = []
    target = {"product": product, "version": version}

    try:
        cves = client.find_cves(product, version)
        results.append({**target, "cves": cves})
    except Exception as exc:
        results.append({**target, "cves": [], "error": str(exc)})

    save_scan(results)
    return render_template_string(
        HTML_TEMPLATE,
        results=results,
        history=get_history(limit=10),
        product=product,
        version=version,
        error="",
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=False)
