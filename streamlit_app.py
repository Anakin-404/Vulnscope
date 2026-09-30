import streamlit as st
import pandas as pd
from nvd_client import NVDClient
from database import init_db, save_scan, get_history

st.set_page_config(page_title="VulnScope", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.main {background-color:#0b1220;}
.block-container {padding-top:2rem;}
.metric-card {
    padding: 18px; border-radius: 12px; background:#111827;
    border:1px solid #263244; text-align:center;
}
</style>
""", unsafe_allow_html=True)

init_db()

st.title("🛡️ VulnScope")
st.caption("Software Vulnerability Discovery & Analysis Tool")

with st.sidebar:
    st.header("Configuration")
    api_key = st.text_input("NVD API Key (optional)", type="password",
                            help="An NVD API key improves rate limits. The app does not store it.")
    st.divider()
    st.info("Enter a product/software name and version. VulnScope queries the NVD CVE database dynamically.")

if "targets" not in st.session_state:
    st.session_state.targets = []

st.subheader("Add Software")
c1, c2, c3 = st.columns([2, 1, 1])
with c1:
    product = st.text_input("Software / Product", placeholder="e.g. Google Chrome")
with c2:
    version = st.text_input("Version", placeholder="e.g. 120.0")
with c3:
    st.write("")
    st.write("")
    if st.button("➕ Add", use_container_width=True):
        if product.strip() and version.strip():
            item = {"product": product.strip(), "version": version.strip()}
            if item not in st.session_state.targets:
                st.session_state.targets.append(item)
        else:
            st.warning("Enter both product and version.")

if st.session_state.targets:
    st.subheader("Scan Targets")
    for i, item in enumerate(st.session_state.targets):
        cols = st.columns([5, 3, 1])
        cols[0].write(item["product"])
        cols[1].write(item["version"])
        if cols[2].button("Remove", key=f"remove_{i}"):
            st.session_state.targets.pop(i)
            st.rerun()

    if st.button("🔎 Scan All Targets", type="primary", use_container_width=True):
        client = NVDClient(api_key=api_key or None)
        results = []

        progress = st.progress(0)
        status = st.empty()

        for i, target in enumerate(st.session_state.targets):
            status.write(f"Scanning **{target['product']} {target['version']}**...")
            try:
                cves = client.find_cves(target["product"], target["version"])
                results.append({**target, "cves": cves})
            except Exception as exc:
                results.append({**target, "cves": [], "error": str(exc)})
            progress.progress((i + 1) / len(st.session_state.targets))

        st.session_state.scan_results = results
        save_scan(results)
        status.success("Scan completed.")

if "scan_results" in st.session_state:
    results = st.session_state.scan_results
    all_cves = [cve for item in results for cve in item.get("cves", [])]

    critical = sum(c.get("severity") == "CRITICAL" for c in all_cves)
    high = sum(c.get("severity") == "HIGH" for c in all_cves)
    medium = sum(c.get("severity") == "MEDIUM" for c in all_cves)
    low = sum(c.get("severity") == "LOW" for c in all_cves)

    st.divider()
    st.subheader("Security Overview")

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Software Scanned", len(results))
    m2.metric("CVEs Found", len(all_cves))
    m3.metric("Critical", critical)
    m4.metric("High", high)
    m5.metric("Medium / Low", medium + low)

    st.subheader("Vulnerability Summary")
    rows = []
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

    for item in results:
        cves = item.get("cves", [])
        highest = max((c.get("severity", "UNKNOWN") for c in cves),
                      key=lambda x: severity_rank.get(x, 0), default="—")
        rows.append({
            "Software": item["product"],
            "Version": item["version"],
            "CVEs Found": len(cves),
            "Highest Severity": highest
        })

    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    st.subheader("CVE Details")
    filter_options = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    severity_filter = st.selectbox("Filter by severity", filter_options)

    selected = []
    for item in results:
        for cve in item.get("cves", []):
            if severity_filter == "ALL" or cve.get("severity", "UNKNOWN") == severity_filter:
                selected.append({**cve, "software": item["product"], "version": item["version"]})

    if selected:
        detail_df = pd.DataFrame([{
            "Software": x["software"],
            "Version": x["version"],
            "CVE": x["id"],
            "Severity": x["severity"],
            "CVSS": x["cvss"],
            "Published": x["published"]
        } for x in selected])
        st.dataframe(detail_df, use_container_width=True, hide_index=True)

        cve_ids = [x["id"] for x in selected]
        chosen_id = st.selectbox("View CVE", cve_ids)
        chosen = next(x for x in selected if x["id"] == chosen_id)

        st.markdown(f"### {chosen['id']}")
        st.write(f"**Severity:** {chosen['severity']}  |  **CVSS:** {chosen['cvss']}")
        st.write(f"**Published:** {chosen['published']}  |  **Last Modified:** {chosen['last_modified']}")
        st.write("**Description**")
        st.write(chosen["description"] or "No description available.")

        st.write("**Affected CPEs**")
        if chosen["affected_cpes"]:
            for cpe in chosen["affected_cpes"][:20]:
                st.code(cpe)
        else:
            st.write("No affected CPE information returned.")

        if chosen["references"]:
            st.write("**References**")
            for ref in chosen["references"]:
                st.markdown(f"- [{ref}]({ref})")
    else:
        st.success("No known CVEs found for the selected software/version with the current NVD matching logic.")

st.divider()
st.subheader("Scan History")
history = get_history(limit=20)
if history:
    st.dataframe(pd.DataFrame(history), use_container_width=True, hide_index=True)
else:
    st.caption("No previous scans yet.")
