"""
User Manual & Operational Guide
Comprehensive guide for senders, recipients, and security evaluators.
Covers end-to-end operation, cryptographic mechanisms, attack detection, and troubleshooting.
"""

import streamlit as st


def render_user_manual():
    st.markdown("""
    <div style="background: linear-gradient(135deg, #0f172a, #1e293b); padding: 1.5rem; border-radius: 12px; border-left: 5px solid #06b6d4; margin-bottom: 1.5rem;">
        <h2 style="margin: 0; color: #f8fafc; font-size: 1.6rem;">📖 User Manual & Operational Guide</h2>
        <p style="margin: 0.4rem 0 0 0; color: #94a3b8; font-size: 0.95rem;">
            A complete guide explaining how to operate the application from beginning to end, understand its security protections, and troubleshoot issues.
        </p>
    </div>
    """, unsafe_allow_html=True)

    manual_nav = st.radio(
        "Select Manual Section:",
        [
            "A. Introduction & Purpose",
            "B. How to Register and Login",
            "C. How to Send a File",
            "D. How to Receive a File",
            "E. Security Mechanisms (Under the Hood)",
            "F. Attack Detection & Alert Flow",
            "G. Transfer Status Explanation",
            "H. Troubleshooting Guide",
            "I. Public & Remote Access Guide"
        ],
        horizontal=True
    )

    st.markdown("---")

    # =========================================================================
    # SECTION A: INTRODUCTION
    # =========================================================================
    if manual_nav == "A. Introduction & Purpose":
        st.markdown("### A. Introduction & Application Purpose")
        st.markdown("""
        #### 🎯 What is this Application?
        The **Innovative Hybrid Cryptographic File Protection and Integrity Verification** platform is designed to allow individuals and organizations to exchange confidential files across untrusted networks with complete mathematical confidence.

        #### 🛡️ How Does it Protect Files During Sharing?
        When files are transferred across the internet or stored on third-party servers, they face three primary threats:
        1. **Eavesdropping (Snooping)**: Unauthorized parties reading confidential documents.
        2. **Tampering (Man-in-the-Middle)**: Malicious actors or transmission errors modifying the contents of files in transit.
        3. **Impersonation (Spoofing)**: Attackers pretending to be a trusted sender.

        This system solves all three problems using an **innovative hybrid architecture**:
        * **AES-256-GCM** ensures absolute confidentiality by encrypting bulk data at gigabit speeds.
        * **RSA-2048-OAEP** eliminates the risk of pre-sharing secret passwords by wrapping session keys using the recipient's public key.
        * **SHA-256 & RSA-2048-PSS** guarantee tamper-evident integrity and provide non-repudiable digital proof of the sender's true identity.
        """)

    # =========================================================================
    # SECTION B: REGISTRATION & LOGIN
    # =========================================================================
    elif manual_nav == "B. How to Register and Login":
        st.markdown("### B. How to Register and Log In")
        st.markdown("""
        Every participant in the system requires an authorized cryptographic identity.

        #### 1. Creating a New Account
        1. Click on **🔐 User Authentication** in the sidebar.
        2. On the right-hand panel (**Register New Account**), enter:
           * **Username**: A unique identifier (e.g., `david`).
           * **Full Name**: Your display name (e.g., `David Miller`).
           * **Email**: Your contact email address.
           * **Password**: A strong password.
        3. Click **✨ Register & Generate RSA Keypair**.
        4. The system will:
           * Securely hash your password using **PBKDF2-HMAC-SHA256** (100,000 iterations).
           * Generate a fresh, unique **2048-bit RSA Keypair** (`Public Key` + `Private Key`).
           * Encrypt your private key with your password-derived key for secure storage in SQLite.

        #### 2. Logging In
        1. Enter your **Username** and **Password** in the login form on the left.
        2. Click **🔓 Log In**.
        3. Once authenticated, your session becomes active and your username appears in the header and sidebar.

        > 💡 **Quick Testing Switcher**: You can also click on any pre-seeded persona (**Alice**, **Bob**, or **Charlie**) under the quick switcher to log in immediately without typing passwords.
        """)

    # =========================================================================
    # SECTION C: HOW TO SEND A FILE
    # =========================================================================
    elif manual_nav == "C. How to Send a File":
        st.markdown("### C. How to Send a File")
        st.markdown("""
        Follow these 5 simple steps to dispatch an end-to-end encrypted file:

        * **Step 1: Log in as the sender**  
          Ensure you are logged in (e.g., as `@alice`).

        * **Step 2: Open Send File**  
          Click on **📤 Send File** in the left sidebar navigation.

        * **Step 3: Upload the file**  
          Under **1. Choose File to Send**, drag and drop or browse to select your file (`.txt`, `.pdf`, `.docx`, `.png`, `.zip`, etc.).  
          The system will instantly display the file's size and calculate its **SHA-256 Checksum**.

        * **Step 4: Select the recipient**  
          Under **2. Select Recipient**, choose the intended receiver from the dropdown list (e.g., `@bob`).  
          Leave the transmission mode as **🟢 Normal Secure Delivery (Deliver Untampered)**.

        * **Step 5: Click Encrypt and Send**  
          Click the blue **🚀 Encrypt and Send File** button.  
          The system executes the hybrid encryption pipeline and dispatches the package. A confirmation message will appear, and the file will be listed in your **Sent Transfers (Outbox)** with status **`PENDING`**.
        """)

    # =========================================================================
    # SECTION D: HOW TO RECEIVE A FILE
    # =========================================================================
    elif manual_nav == "D. How to Receive a File":
        st.markdown("### D. How to Receive a File")
        st.markdown("""
        Follow these steps when you are the designated recipient:

        * **Step 1: Log in as the recipient**  
          Switch or log into your recipient account (e.g., `@bob`).

        * **Step 2: Open Inbox**  
          Click on **📥 Receive File** in the left sidebar navigation. You will see a table of all files sent specifically to you.

        * **Step 3: Select the incoming file**  
          From the dropdown under **File Decryption & Integrity Verification**, select the package you want to open.

        * **Step 4: Click Decrypt and Verify**  
          Click the **🔑 Decrypt and Verify File** button.  
          The application will:
          1. Decrypt the AES session key using your private key.
          2. Decrypt the file payload using AES-256-GCM.
          3. Recompute the SHA-256 hash of the recovered file and check against the original.
          4. Mathematically verify the sender's RSA-PSS digital signature.

        * **Step 5: View or download the recovered file**  
          * If untampered, a **GREEN VERIFIED** notification appears.
          * If text/document, read the content directly in the **On-Screen Plaintext Preview**.
          * Click **⬇️ Download Original File** to save the recovered file to your computer.
        """)

    # =========================================================================
    # SECTION E: SECURITY MECHANISMS
    # =========================================================================
    elif manual_nav == "E. Security Mechanisms (Under the Hood)":
        st.markdown("### E. Security Mechanisms (Explained in Simple Terms)")
        st.markdown("""
        | Technology | Standard / Key Size | Simple Explanation of Its Role |
        | :--- | :--- | :--- |
        | **AES-256-GCM** | Symmetric Cipher (256-bit key) | **Fast File Encryption**: Scrambles the file data into unreadable ciphertext. GCM (Galois/Counter Mode) adds an authenticated 128-bit MAC tag that immediately detects if any encrypted byte is altered. |
        | **RSA-2048-OAEP** | Asymmetric Cipher (2048-bit key) | **Session Key Protection**: Safely wraps the 256-bit AES key using the recipient's public key. Only the recipient's matching private key can unwrap it, solving the key-exchange problem without pre-shared passwords. |
        | **SHA-256** | Cryptographic Hash (256-bit digest) | **Integrity Verification**: Generates a 64-character unique fingerprint of the file. Changing even a single letter in the file completely changes this fingerprint (Avalanche Effect). |
        | **RSA-2048-PSS** | Digital Signature Scheme | **Sender Authentication & Non-Repudiation**: The sender signs the file hash with their private key. The receiver verifies it using the sender's public key, proving the file came from the real sender and not an imposter. |
        """)

    # =========================================================================
    # SECTION F: ATTACK DETECTION
    # =========================================================================
    elif manual_nav == "F. Attack Detection & Alert Flow":
        st.markdown("### F. Attack Detection & Alert System")
        st.markdown("""
        #### 🔍 How Does SHA-256 Detect Changes?
        SHA-256 is an irreversible cryptographic function. If an attacker intercepts the transmission and alters even a single bit (for example, changing a $1,000 transfer to $9,000):
        * The calculated SHA-256 digest on the receiver's machine will completely diverge from the sender's signed digest.
        * The AES-256-GCM authentication tag verification will also fail.

        #### 🚨 The RED SECURITY ALERT (When Modified):
        If an attack or modification occurs:
        1. A prominent **RED SECURITY ALERT** banner is shown on the recipient's screen.
        2. The message informs the user that **File Integrity Verification has Failed**.
        3. **Access & Download are Permanently Blocked**: Corrupted or malicious payloads are never released to the user's hard drive.
        4. The transfer status in SQLite changes to **`ATTACK DETECTED`**, and the incident is recorded in the security audit log.

        #### ✅ The GREEN VERIFIED Notification (When Untampered):
        If the file has not been altered:
        1. A bright **GREEN VERIFIED** notification confirms authentic delivery.
        2. Both the digital signature and SHA-256 hash match 100%.
        3. The recipient is granted immediate access to view and download the restored file.
        4. The transfer status changes to **`VERIFIED`**.
        """)

    # =========================================================================
    # SECTION G: TRANSFER STATUS EXPLANATION
    # =========================================================================
    elif manual_nav == "G. Transfer Status Explanation":
        st.markdown("### G. Transfer Status Lifecycle")
        st.markdown("""
        Every transfer transitions through clear, standardized statuses:

        ```
        [Sender Sends File]
                 │
                 ▼
            [PENDING]  ─── (Waiting for recipient to open & verify)
                 │
                 ├──► [VERIFIED]         (Cryptographic checks pass 100% -> File readable & downloadable)
                 │
                 └──► [ATTACK DETECTED]  (Integrity check or signature failed -> File blocked)
        ```

        * ⏳ **PENDING**: The sender has encrypted and dispatched the file. It is waiting in the recipient's inbox to be processed.
        * 📥 **RECEIVED**: The encrypted package has arrived at the recipient's endpoint and is queued for verification.
        * ✅ **VERIFIED**: The recipient's private key unwrapped the AES key, the SHA-256 checksum matched the original, and the sender's signature was authenticated. The file is accessible.
        * 🚨 **ATTACK DETECTED**: Tampering or corruption occurred in transit. The AES-GCM tag or SHA-256 hash mismatched, or the signature was invalid. The file is locked down.
        """)

    # =========================================================================
    # SECTION H: TROUBLESHOOTING GUIDE
    # =========================================================================
    elif manual_nav == "H. Troubleshooting Guide":
        st.markdown("### H. Troubleshooting Guide")
        st.markdown("""
        #### 1. Login Failures
        * **Problem**: "Invalid username or password" or "Username not found".
        * **Solution**: Ensure you typed the lowercase username correctly. If testing, click one of the quick persona buttons (**Alice** or **Bob**) to log in with verified demo credentials.

        #### 2. File Upload Errors
        * **Problem**: File upload is slow or times out.
        * **Solution**: Ensure your file is readable on your disk. The system supports any file type (`.txt`, `.pdf`, `.png`, `.zip`, etc.).

        #### 3. Decryption Failures
        * **Problem**: "Unable to decrypt AES session key with provided private key".
        * **Solution**: You are attempting to open a file that was encrypted for a *different* recipient. Log in as the exact user chosen as the recipient by the sender.

        #### 4. Invalid Digital Signatures
        * **Problem**: Signature check returns false.
        * **Solution**: The sender's public key did not match the private key used to sign the file, or the sender's identity has been spoofed.

        #### 5. File Integrity Verification Failures (Attack Alert)
        * **Problem**: The red alert `🚨 RED SECURITY ALERT: FILE INTEGRITY VERIFICATION FAILED!` appears.
        * **Explanation**: This is the core defense mechanism working correctly. It indicates that the ciphertext or file bytes were modified in transit (such as during an attack simulation). Do not attempt to force open the file; request the sender to re-transmit the clean file.
        """)

    # =========================================================================
    # SECTION I: PUBLIC & REMOTE ACCESS GUIDE
    # =========================================================================
    elif manual_nav == "I. Public & Remote Access Guide":
        st.markdown("### 🌐 I. Public & Remote Access Guide (Sharing with Anyone)")
        st.markdown("""
        The application is configured to run on network interface `0.0.0.0`, allowing anyone across different devices, Wi-Fi networks, and locations to collaborate securely.

        ---

        #### 📶 1. Local Network / Same Wi-Fi Access (LAN)
        If your evaluator, friend, or teammate is on the **same Wi-Fi router or campus network**:
        * Run the application with:
          ```bash
          python run_app.py
          ```
        * Check the **Network (LAN) URL** displayed in your terminal (e.g. `http://10.72.87.56:8501`).
        * Any smartphone, laptop, or tablet on your Wi-Fi can directly enter this URL in Google Chrome or Safari to send and receive files.

        ---

        #### 🌍 2. Instant Public Internet Access (Worldwide via Tunnel)
        To share this website with **anyone across the internet worldwide** (even on different cellular data or networks):

        ##### 🚀 Method A: One-Click Launcher (Recommended)
        Double-click the included Windows batch file:
        * **`start_public_server.bat`** (or run `python run_app.py --public`)
        * It starts the server and automatically opens a secure public HTTPS tunnel.
        * Copy the generated **🌐 PUBLIC INTERNET URL** (e.g., `https://xxxxx.loca.lt`) and share it with anyone!

        ##### 🛠️ Method B: Manual Public Tunneling Options
        * **Option 1: Node.js Localtunnel (Zero configuration)**
          ```bash
          npx localtunnel --port 8501
          ```
          *(When opening for the first time, click "Click to Continue" or enter your public IP).*
        * **Option 2: Cloudflare Tunnel (Free & Fast)**
          ```bash
          cloudflared tunnel --url http://localhost:8501
          ```
        * **Option 3: Built-in Windows SSH Tunnel (No tools to install)**
          ```bash
          ssh -R 80:localhost:8501 nokey@localhost.run
          ```

        ---

        #### ☁️ 3. Permanent Free Cloud Deployment (24/7 Public Link)
        To keep the website online 24/7 on a permanent public URL (e.g. `https://my-crypto-vault.streamlit.app`):
        1. **Create a GitHub repository** and push the project files to it.
        2. Visit **[share.streamlit.io](https://share.streamlit.io)** and log in with GitHub.
        3. Click **"New app"**, select your repository, set the main file path to `app.py`, and click **Deploy**.
        4. In under 2 minutes, your website is globally hosted and accessible by anyone in the world!
        """)
