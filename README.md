# VulnScope 🛡️

**VulnScope — Software Vulnerability Discovery & Analysis Tool**

VulnScope is a beginner-friendly Python cybersecurity application that accepts a software/product name and version, queries the NVD CVE database, and presents relevant vulnerability information in a Streamlit dashboard.

## Features

- Search any software/product supported by NVD
- Specify a product version
- Dynamic CVE retrieval using the NVD REST API
- CVE ID, CVSS score and severity
- Vulnerability descriptions
- Published and modified dates
- Affected CPE information
- References
- Severity filtering
- Multiple scan targets
- SQLite scan history
- Dashboard summary
- API/rate-limit error handling

## Tech Stack

- Python
- Streamlit
- NVD REST API
- Requests
- JSON
- SQLite
- Pandas

## Run locally

```bash
python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the application:

```bash
streamlit run app.py
```

Then open the local Streamlit URL shown in the terminal.

## NVD API key

The application works without an API key, but NVD rate limits are stricter without one. You can paste an NVD API key into the Streamlit sidebar for better rate limits.

The key is used only for the current session and is not saved by VulnScope.

## Important limitation

CVE-to-product/version matching is complicated because vulnerability databases use CPE identifiers and version ranges. VulnScope uses NVD CPE/CVE data and performs conservative matching, but it should be treated as a vulnerability discovery aid rather than proof that a system is secure or insecure.

Always verify important findings against the original NVD record and the vendor's security advisory.

## Suggested future improvements

- Better CPE selection and product disambiguation
- Export reports to PDF/CSV
- CVE detail pages
- Vendor advisory links
- Scheduled scanning
- Asset inventory
- Authentication
- Docker deployment
- Unit and integration tests
