# CyberGuard — Python Cybersecurity Toolkit

A beginner-friendly Streamlit website with three modules:
1. Brute-force attack pattern detection from uploaded login logs.
2. File encryption and decryption using Fernet authenticated encryption.
3. Rule-based phishing email and URL analysis.

## Requirements
- Python 3.10–3.13 recommended
- Internet connection for the initial package installation only

## Run on Windows
1. Extract the ZIP file.
2. Open the extracted `CyberGuard` folder in PyCharm, VS Code, or a terminal.
3. Open the terminal in that folder.
4. Create a virtual environment (recommended):

   ```powershell
   py -3.12 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

   If Python 3.12 is not installed, use an installed supported Python version.

5. Install packages:

   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

6. Start the website:

   ```powershell
   streamlit run app.py
   ```

7. Streamlit will show a local URL, normally `http://localhost:8501`. Open it in your browser.

## Modules
### Brute-Force Detection
Upload a CSV with `ip_address` and `result` columns. Optional columns are `time` and `user`.
Supported failure values include `failed`, `failure`, `fail`, `denied`, `invalid`, and `unsuccessful`.
Use the included sample CSV from the page to test it.

### File Encryption
Generate a Fernet key, keep it safely, then encrypt a file. Use that same key to decrypt the `.encrypted` file. Do not lose the key or share it with others.

### Phishing Analysis
Enter the sender, optional Reply-To address, subject, and body. The tool checks for common suspicious wording and URL indicators. Results are not proof that an email is malicious or safe.

## Important
This is a student demonstration project, not a production security product. It does not monitor live systems or use threat-intelligence feeds. Rule-based checks can miss threats or flag legitimate content. Run locally for private files and only analyze data you are authorized to use.
