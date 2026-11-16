# Innovative Hybrid Cryptographic File Protection and Integrity Verification

An enterprise-grade, multi-module cybersecurity web application that integrates **Symmetric Encryption (AES-256-GCM)**, **Asymmetric Cryptography (RSA-2048-OAEP & RSA-PSS)**, **Cryptographic Hashing (SHA-256)**, and **Relational Persistence (SQLite)** into a unified, user-friendly **Streamlit** dashboard.

---

## 🧭 Application Structure & Navigation

The application contains 6 streamlined pages accessible from the left sidebar:
1. **🏠 Home / Dashboard**: Telemetry metrics, 3-step workflow, and live network access endpoints.
2. **🔐 User Authentication**: Multi-user registration and login with PBKDF2-HMAC-SHA256 and automatic 2048-bit RSA keypair generation.
3. **📤 Send File**: Upload file, select recipient, encrypt with AES-256-GCM, wrap AES key with RSA-OAEP, compute SHA-256 digest, sign with RSA-PSS, and dispatch. Includes an optional **Simulate In-Transit Attack** toggle for evaluation.
4. **📥 Receive File**: Recipient inbox, RSA private key decryption, sender signature authentication, and SHA-256 integrity verification. Prominently displays **RED SECURITY ALERT** on tampering or **GREEN VERIFIED** on clean delivery.
5. **🛡️ Security Monitoring**: Live audit log explorer, attack alerts, and CSV export.
6. **📖 User Manual**: Complete operational and technical guide including public and remote access instructions.

---

## 🌐 Public, Local Network (LAN) & Cloud Access

The application is configured to bind to `0.0.0.0:8501`, enabling access across all network interfaces.

### 1. Same Wi-Fi / Local Network Access (LAN)
Anyone connected to your local Wi-Fi or campus network can open the web app on any device:
* Start the server with `python run_app.py`.
* Note the **Network (LAN) URL** printed in the terminal:
  `http://<YOUR_LAN_IP>:8501` (e.g. `http://10.72.87.56:8501`).
* Any phone, tablet, or laptop on the same Wi-Fi can open this link directly in Google Chrome or Safari.

### 2. Instant Worldwide Public Access (Tunneling)
To share this website with **anyone in the world over the internet**:
* **Option A (One-Click Launcher)**: Double-click **`start_public_server.bat`** (or run `python run_app.py --public`).
  It automatically starts Streamlit and opens a secure public HTTPS tunnel via `localtunnel` (`https://xxxx.loca.lt`).
* **Option B (Node.js localtunnel)**:
  ```bash
  npx localtunnel --port 8501
  ```
* **Option C (Cloudflare Tunnel)**:
  ```bash
  cloudflared tunnel --url http://localhost:8501
  ```
* **Option D (Windows Built-in SSH Tunnel)**:
  ```bash
  ssh -R 80:localhost:8501 nokey@localhost.run
  ```

### 3. Permanent 24/7 Cloud Deployment (Streamlit Community Cloud)
To host the app permanently online for free:
1. Push this directory to your GitHub account.
2. Go to [share.streamlit.io](https://share.streamlit.io) and log in with GitHub.
3. Select your repository, set the main file path to `app.py`, and click **Deploy**.
4. In under 2 minutes, you get a permanent URL like `https://my-crypto-vault.streamlit.app`.

---

## 💻 Technology & Cryptographic Stack

| Layer | Technology | Details |
| :--- | :--- | :--- |
| **Language** | Python 3.10+ | Native execution |
| **Frontend** | Streamlit | Responsive Cyber Dark UI with real-time reactive state |
| **Symmetric Encryption** | AES-256-GCM | 256-bit key, 12-byte IV/Nonce, 16-byte Tag |
| **Asymmetric Encryption** | RSA-2048-OAEP | MGF1(SHA-256), SHA-256 digest |
| **Digital Signatures** | RSA-2048-PSS | Probabilistic Signature Scheme with SHA-256 |
| **Hashing** | SHA-256 | 256-bit cryptographic digest |
| **Database** | SQLite 3 | WAL mode with automatic schema migration |
| **Network Interfaces** | `0.0.0.0:8501` | Public tunnel & local network ready |

---

## 🚀 How to Run the Application

### 1. Launch with Public & Network Access
```powershell
# Standard local & LAN access
python run_app.py

# Public worldwide access with instant HTTPS tunnel
python run_app.py --public

# Or double-click the Windows batch file:
start_public_server.bat
```

---

## 👥 Demo Personas (Pre-Seeded)

For fast testing of multi-user transfers and sender-recipient flows, three demo personas are pre-configured:
- **Alice** (Sender): `alice` / `Alice@123`
- **Bob** (Recipient): `bob` / `Bob@123`
- **Charlie** (Peer/Auditor): `charlie` / `Charlie@123`

You can switch personas with a single click in Module 1 or register custom user accounts.
