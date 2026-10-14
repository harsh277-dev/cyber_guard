import io
import re
import csv
import ipaddress
from datetime import datetime
from urllib.parse import urlparse

import pandas as pd
import streamlit as st
from cryptography.fernet import Fernet, InvalidToken

st.set_page_config(page_title="CyberGuard | Cybersecurity Toolkit", page_icon="🛡️", layout="wide")

# ---------- Styling ----------
st.markdown("""
<style>
.main {background: #f7f9fc;}
.block-container {padding-top: 1.5rem; max-width: 1200px;}
.hero {padding: 1.5rem 1.7rem; border-radius: 18px; color: white;
       background: linear-gradient(120deg, #101d3a, #174b78);}
.hero h1 {margin: 0; font-size: 2.25rem;}
.hero p {margin: .45rem 0 0; color: #e2efff;}
.small-muted {color: #65748b; font-size: .9rem;}
.module-card {padding: 1rem; border: 1px solid #e3eaf3; border-radius: 14px; background: white;}
</style>
""", unsafe_allow_html=True)

# ---------- Helpers ----------
def read_login_csv(uploaded_file):
    try:
        df = pd.read_csv(uploaded_file)
    except Exception:
        uploaded_file.seek(0)
        df = pd.read_csv(uploaded_file, sep=None, engine="python")
    df.columns = [str(c).strip().lower().replace(" ", "_") for c in df.columns]
    aliases = {
        "ip": "ip_address", "source_ip": "ip_address", "src_ip": "ip_address",
        "username": "user", "user_name": "user", "status": "result",
        "login_status": "result", "timestamp": "time", "date": "time"
    }
    df = df.rename(columns={c: aliases.get(c, c) for c in df.columns})
    required = {"ip_address", "result"}
    if not required.issubset(df.columns):
        raise ValueError("CSV must include columns for IP address and result/status. See the sample CSV.")
    df["ip_address"] = df["ip_address"].astype(str).str.strip()
    df["result"] = df["result"].astype(str).str.strip().str.lower()
    if "time" not in df.columns:
        df["time"] = "Not provided"
    if "user" not in df.columns:
        df["user"] = "Unknown"
    return df

def is_failed(value):
    v = str(value).lower().strip()
    return v in {"failed", "failure", "fail", "denied", "invalid", "unsuccessful"} or "fail" in v

def analyze_logs(df, threshold):
    df = df.copy()
    df["is_failed"] = df["result"].apply(is_failed)
    failed = df[df["is_failed"]]
    counts = failed.groupby("ip_address").size().rename("failed_attempts")
    report = counts.reset_index()
    report["risk"] = report["failed_attempts"].apply(
        lambda n: "High" if n >= threshold * 2 else ("Medium" if n >= threshold else "Low")
    )
    report = report.sort_values("failed_attempts", ascending=False)
    return df, report, failed

def inspect_url(raw_url):
    raw_url = raw_url.strip().strip("<>()[]{}'\".,;")
    if not raw_url:
        return None
    candidate = raw_url if "://" in raw_url else "http://" + raw_url
    try:
        parsed = urlparse(candidate)
        host = parsed.hostname or ""
    except Exception:
        return {"url": raw_url, "flags": ["Could not parse URL"], "risk": "Suspicious"}
    flags = []
    if not host:
        flags.append("No recognizable hostname")
    if parsed.scheme.lower() == "http":
        flags.append("Uses HTTP rather than HTTPS")
    if "@" in parsed.netloc:
        flags.append("Contains @ in URL authority")
    if re.search(r"(login|verify|secure|account|update|password|banking|wallet)", raw_url, re.I):
        flags.append("Contains words often used in credential lures")
    if re.search(r"(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly)", host, re.I):
        flags.append("Uses a URL-shortening domain")
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
        flags.append("Uses an IP address instead of a typical domain")
    if host.count("-") >= 3:
        flags.append("Domain contains several hyphens")
    if len(host) > 45:
        flags.append("Unusually long hostname")
    if host.startswith("xn--") or ".xn--" in host:
        flags.append("Contains an internationalized/punycode domain")
    risk = "High" if len(flags) >= 3 else ("Medium" if len(flags) >= 1 else "Low")
    return {"url": raw_url, "host": host, "flags": flags, "risk": risk}

def analyze_email(sender, reply_to, subject, body):
    findings = []
    sender = sender.strip()
    reply_to = reply_to.strip()
    subject = subject.strip()
    body = body.strip()
    if not sender:
        findings.append(("Medium", "Sender address is missing."))
    sender_domain = sender.rsplit("@", 1)[-1].lower() if "@" in sender else ""
    reply_domain = reply_to.rsplit("@", 1)[-1].lower() if "@" in reply_to else ""
    if sender and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", sender):
        findings.append(("Medium", "Sender address format looks unusual."))
    if reply_to:
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", reply_to):
            findings.append(("Medium", "Reply-to address format looks unusual."))
        elif sender_domain and sender_domain != reply_domain:
            findings.append(("High", f"Reply-to domain ({reply_domain}) differs from sender domain ({sender_domain})."))
    text = (subject + " " + body).lower()
    lure_terms = {
        "urgent": "Urgency language",
        "immediately": "Urgency language",
        "verify your account": "Account-verification request",
        "password": "Password-related wording",
        "suspended": "Threat of account suspension",
        "prize": "Prize/reward lure",
        "gift card": "Gift-card lure",
        "wire transfer": "Payment-transfer request",
        "click here": "Call to click a link",
        "confirm your account": "Account-confirmation request",
        "limited time": "Time-pressure wording",
    }
    for term, label in lure_terms.items():
        if term in text:
            findings.append(("Medium", f"{label}: “{term}”."))
    urls = re.findall(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+|(?<!@)\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>\"']*)?", body)
    url_results = []
    seen = set()
    for url in urls:
        cleaned = url.rstrip(".,;)")
        if cleaned.lower() not in seen:
            seen.add(cleaned.lower())
            result = inspect_url(cleaned)
            if result:
                url_results.append(result)
                for flag in result["flags"]:
                    findings.append(("High" if result["risk"] == "High" else "Medium", f"URL {cleaned}: {flag}."))
    if not findings:
        findings.append(("Low", "No obvious indicators were found by these basic checks. This does not prove the email is safe."))
    max_level = max(({"Low": 1, "Medium": 2, "High": 3}.get(level, 1) for level, _ in findings), default=1)
    overall = {1: "Low", 2: "Medium", 3: "High"}[max_level]
    return findings, url_results, overall

def make_sample_csv():
    return """time,ip_address,user,result
2026-10-10 09:00:00,192.0.2.10,student1,success
2026-10-10 09:01:00,198.51.100.23,admin,failed
2026-10-10 09:01:10,198.51.100.23,admin,failed
2026-10-10 09:01:20,198.51.100.23,admin,failed
2026-10-10 09:01:30,198.51.100.23,admin,failed
2026-10-10 09:02:00,203.0.113.8,student2,success
2026-10-10 09:03:00,203.0.113.45,faculty,failed
"""

# ---------- Sidebar ----------
st.sidebar.markdown("## 🛡️ CyberGuard")
st.sidebar.caption("Cybersecurity Toolkit")
page = st.sidebar.radio("Navigate", [
    "Dashboard", "Brute-Force Detection", "File Encryption", "Phishing Analysis", "About"
])
st.sidebar.divider()
st.sidebar.caption("Educational prototype • Run locally for private files")

# ---------- Dashboard ----------
if page == "Dashboard":
    st.markdown("""
    <div class="hero">
      <h1>🛡️ CyberGuard</h1>
      <p>A simple Python-based cybersecurity toolkit for detecting suspicious login activity, protecting files, and checking possible phishing emails.</p>
    </div>
    """, unsafe_allow_html=True)
    st.write("")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown('<div class="module-card">', unsafe_allow_html=True)
        st.subheader("🔎 Brute-Force Detection")
        st.write("Analyze login logs and flag IP addresses with repeated failed attempts.")
        st.caption("Security log analysis")
        st.markdown("</div>", unsafe_allow_html=True)
        if st.button("Open detection module", use_container_width=True):
            st.session_state["navigate_to"] = "Brute-Force Detection"
    with c2:
        st.markdown('<div class="module-card">', unsafe_allow_html=True)
        st.subheader("🔐 File Encryption")
        st.write("Encrypt a file or decrypt a previously encrypted file using a key.")
        st.caption("Data protection")
        st.markdown("</div>", unsafe_allow_html=True)
        if st.button("Open encryption module", use_container_width=True):
            st.session_state["navigate_to"] = "File Encryption"
    with c3:
        st.markdown('<div class="module-card">', unsafe_allow_html=True)
        st.subheader("✉️ Phishing Analysis")
        st.write("Inspect email details, wording, and URLs for possible warning signs.")
        st.caption("Email security / basic forensics")
        st.markdown("</div>", unsafe_allow_html=True)
        if st.button("Open phishing module", use_container_width=True):
            st.session_state["navigate_to"] = "Phishing Analysis"
    if "navigate_to" in st.session_state:
        target = st.session_state.pop("navigate_to")
        st.info(f"Use the sidebar to open **{target}**.")
    st.divider()
    st.subheader("How to use")
    st.markdown("""
    1. Choose a module from the left sidebar.
    2. Upload a login-log CSV, select a file for encryption/decryption, or enter email details.
    3. Review the findings and download a report when available.
    """)
    st.warning("This project is for learning and demonstration. A low-risk result is not a guarantee that an account, file, URL, or email is safe.")

# ---------- Brute-force detection ----------
elif page == "Brute-Force Detection":
    st.title("🔎 Brute-Force Attack Detection")
    st.write("Upload a CSV of login events. The tool groups failed attempts by IP address and flags repeated failures.")
    with st.expander("CSV format and sample"):
        st.write("Required columns: `ip_address` and `result`. Optional columns: `time` and `user`. Result values such as `failed` and `success` are supported.")
        st.code(make_sample_csv(), language="csv")
        st.download_button("Download sample login CSV", make_sample_csv().encode("utf-8"), "sample_login_logs.csv", "text/csv")
    uploaded = st.file_uploader("Upload login logs (.csv)", type=["csv"], key="login_csv")
    threshold = st.slider("Failed attempts to flag an IP", min_value=2, max_value=15, value=4)
    if uploaded:
        try:
            df = read_login_csv(uploaded)
            full_df, report, failed = analyze_logs(df, threshold)
            total = len(full_df)
            fail_count = len(failed)
            flagged = int((report["failed_attempts"] >= threshold).sum()) if not report.empty else 0
            a, b, c = st.columns(3)
            a.metric("Total login events", total)
            b.metric("Failed attempts", fail_count)
            c.metric("IP addresses flagged", flagged)
            if report.empty:
                st.success("No failed login events were found in this file.")
            else:
                st.subheader("IP risk summary")
                st.dataframe(report, use_container_width=True, hide_index=True)
                st.subheader("Login events")
                st.dataframe(full_df.drop(columns=["is_failed"]), use_container_width=True, hide_index=True)
                st.download_button("Download detection report", report.to_csv(index=False).encode("utf-8"), "brute_force_report.csv", "text/csv")
                if flagged:
                    st.warning(f"{flagged} IP address(es) met or exceeded the threshold of {threshold} failed attempts.")
                else:
                    st.info("No IP address met the selected threshold.")
            st.caption("This flags patterns in the supplied logs; it does not monitor a live system or prove that an attack occurred.")
        except Exception as e:
            st.error(f"Could not analyze this CSV: {e}")

# ---------- File encryption ----------
elif page == "File Encryption":
    st.title("🔐 File Encryption & Decryption")
    st.write("Secure your files using Fernet encryption.")

    from cryptography.fernet import Fernet, InvalidToken

    # Initialize the key
    if "fernet_key" not in st.session_state:
        st.session_state["fernet_key"] = ""

    def generate_key():
        st.session_state["fernet_key"] = (
            Fernet.generate_key().decode("utf-8")
        )

    encrypt_tab, decrypt_tab = st.tabs(
        ["Encrypt a file", "Decrypt a file"]
    )

    # -------- ENCRYPTION --------
    with encrypt_tab:
        st.subheader("Encrypt your file")

        uploaded_file = st.file_uploader(
            "Choose a file",
            key="file_to_encrypt"
        )

        st.button(
            "🔑 Generate new encryption key",
            on_click=generate_key,
            key="generate_fernet_key"
        )

        encryption_key = st.text_input(
            "Encryption key",
            key="fernet_key"
        )

        if st.button(
            "🔒 Encrypt file",
            type="primary",
            key="encrypt_button"
        ):
            if uploaded_file is None:
                st.error("Please select a file first.")

            elif not encryption_key.strip():
                st.error("Please generate an encryption key first.")

            else:
                try:
                    cipher = Fernet(
                        encryption_key.strip().encode("utf-8")
                    )

                    encrypted_data = cipher.encrypt(
                        uploaded_file.getvalue()
                    )

                    st.success("File encrypted successfully!")

                    st.download_button(
                        "⬇️ Download encrypted file",
                        data=encrypted_data,
                        file_name=uploaded_file.name + ".encrypted",
                        mime="application/octet-stream",
                        key="download_encrypted"
                    )

                    st.download_button(
                        "🔑 Download encryption key",
                        data=encryption_key.encode("utf-8"),
                        file_name="cyberguard_key.txt",
                        mime="text/plain",
                        key="download_key"
                    )

                except Exception as error:
                    st.error(
                        f"Encryption failed: {error}"
                    )

    # -------- DECRYPTION --------
    with decrypt_tab:
        st.subheader("Decrypt your file")

        encrypted_file = st.file_uploader(
            "Choose an encrypted file",
            key="file_to_decrypt"
        )

        decryption_key = st.text_input(
            "Enter your encryption key",
            type="password",
            key="decryption_key"
        )

        output_filename = st.text_input(
            "Name for the restored file",
            value="restored_file.txt",
            key="restored_filename"
        )

        if st.button(
            "🔓 Decrypt file",
            type="primary",
            key="decrypt_button"
        ):
            if encrypted_file is None:
                st.error("Please upload an encrypted file.")

            elif not decryption_key.strip():
                st.error("Please enter your encryption key.")

            else:
                try:
                    cipher = Fernet(
                        decryption_key.strip().encode("utf-8")
                    )

                    original_data = cipher.decrypt(
                        encrypted_file.getvalue()
                    )

                    st.success("File decrypted successfully!")

                    st.download_button(
                        "⬇️ Download restored file",
                        data=original_data,
                        file_name=(
                            output_filename.strip()
                            or "restored_file.txt"
                        ),
                        mime="application/octet-stream",
                        key="download_restored"
                    )

                except (InvalidToken, ValueError):
                    st.error(
                        "Decryption failed. Check your key "
                        "or encrypted file."
                    )

                except Exception as error:
                    st.error(
                        f"Decryption failed: {error}"
                    )
# ---------- Phishing analysis ----------
elif page == "Phishing Analysis":
    st.title("✉️ Phishing Email Analysis")
    st.write("Enter email details to check for common warning signs. This is a rule-based educational screening tool, not a definitive verdict.")
    with st.expander("Example suspicious email"):
        st.code("From: support@example-security.test\nReply-To: account-help@different-domain.test\nSubject: Urgent: verify your account immediately\n\nYour account may be suspended. Click here to verify your password: http://192.0.2.99/login")
        if st.button("Load example into fields"):
            st.session_state["sample_sender"] = "support@example-security.test"
            st.session_state["sample_reply"] = "account-help@different-domain.test"
            st.session_state["sample_subject"] = "Urgent: verify your account immediately"
            st.session_state["sample_body"] = "Your account may be suspended. Click here to verify your password: http://192.0.2.99/login"
    with st.form("email_form"):
        sender = st.text_input("Sender email address", value=st.session_state.get("sample_sender", ""))
        reply_to = st.text_input("Reply-To address (optional)", value=st.session_state.get("sample_reply", ""))
        subject = st.text_input("Email subject", value=st.session_state.get("sample_subject", ""))
        body = st.text_area("Email body / message", value=st.session_state.get("sample_body", ""), height=180)
        submitted = st.form_submit_button("Analyze email", type="primary")
    if submitted:
        findings, urls, overall = analyze_email(sender, reply_to, subject, body)
        if overall == "High":
            st.error(f"Overall indicator: {overall} risk")
        elif overall == "Medium":
            st.warning(f"Overall indicator: {overall} risk")
        else:
            st.success(f"Overall indicator: {overall} risk")
        st.caption("Risk is based only on the rules in this prototype; confirm suspicious messages through a trusted channel.")
        st.subheader("Findings")
        st.dataframe(pd.DataFrame(findings, columns=["Level", "Finding"]), use_container_width=True, hide_index=True)
        if urls:
            st.subheader("URLs found")
            st.dataframe(pd.DataFrame([{
                "URL": u["url"], "Hostname": u.get("host", ""),
                "Risk": u["risk"], "Warnings": "; ".join(u["flags"]) if u["flags"] else "No rule-based warnings"
            } for u in urls]), use_container_width=True, hide_index=True)
        report_text = "CyberGuard Email Analysis Report\n"
        report_text += f"Overall indicator: {overall}\nSender: {sender}\nReply-To: {reply_to}\nSubject: {subject}\n\nFindings:\n"
        report_text += "\n".join(f"[{level}] {finding}" for level, finding in findings)
        st.download_button("Download email analysis report", report_text.encode("utf-8"), "email_analysis_report.txt", "text/plain")

# ---------- About ----------
elif page == "About":
    st.title("About CyberGuard")
    st.write("CyberGuard is a beginner-friendly cybersecurity project that brings three small tools into one web interface.")
    st.subheader("Technology used")
    st.markdown("""
    - **Python** — application logic
    - **Streamlit** — web interface and navigation
    - **Pandas** — reading and analyzing login-log CSV files
    - **Cryptography (Fernet)** — authenticated file encryption
    - **Regular expressions and URL parsing** — basic email and URL checks
    """)
    st.subheader("Limitations")
    st.markdown("""
    - Brute-force detection analyzes uploaded logs only; it does not connect to real login servers.
    - Phishing detection uses simple rules and may produce false positives or miss sophisticated attacks.
    - Encryption keys must be stored securely by the user. If a key is lost, the encrypted file cannot be recovered.
    - Do not upload confidential company, college, or personal data unless you understand where the app is running and who can access it.
    """)
    st.success("Designed as a local educational prototype for a student project.")
