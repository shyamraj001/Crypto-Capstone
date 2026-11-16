"""
Innovative Hybrid Cryptographic File Protection and Integrity Verification
Main Streamlit Application
"""

import sys
import os
import socket
import streamlit as st
import pandas as pd

# Ensure current project directory is on path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

import database
import crypto_engine
from modules.module1_auth import render_module1
from modules.module2_encryption import render_send_file
from modules.module4_transfer import render_receive_file
from modules.module3_integrity import render_security_monitoring
from modules.manual import render_user_manual


def get_lan_ip() -> str:
    """Returns the local network IPv4 address of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

# Initialize Database Schema & Seed Data
database.init_db()

# Streamlit Page Configuration
st.set_page_config(
    page_title="Innovative Hybrid Cryptographic File Protection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyber Dark CSS Styling
st.markdown("""
<style>
    /* Dark Theme Base */
    .stApp {
        background-color: #0b0f19;
        color: #f1f5f9;
        font-family: 'Inter', system-ui, -apple-system, sans-serif;
    }
    
    /* Top Header */
    .main-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
        border: 1px solid #1e293b;
        padding: 1.4rem 1.8rem;
        border-radius: 12px;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.4);
        margin-bottom: 1.5rem;
    }
    
    .main-title {
        color: #ffffff;
        font-weight: 800;
        font-size: 1.7rem;
        letter-spacing: -0.02em;
        margin: 0;
        background: linear-gradient(90deg, #60a5fa, #a78bfa, #34d399);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    
    .sub-title {
        color: #94a3b8;
        font-size: 0.92rem;
        margin-top: 0.3rem;
    }
    
    /* Badges */
    .badge-container {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin-top: 8px;
    }
    
    .crypto-badge {
        display: inline-block;
        font-size: 0.72rem;
        font-weight: 600;
        padding: 3px 9px;
        border-radius: 6px;
        text-transform: uppercase;
        letter-spacing: 0.04em;
    }
    .badge-aes { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }
    .badge-rsa { background: rgba(139, 92, 246, 0.2); color: #a78bfa; border: 1px solid rgba(139, 92, 246, 0.4); }
    .badge-sha { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
    .badge-db  { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }
    
    div[data-testid="stSidebar"] {
        background-color: #0d1322;
        border-right: 1px solid #1e293b;
    }
    
    div[data-testid="stMetricValue"] {
        color: #38bdf8;
        font-family: monospace;
    }
</style>
""", unsafe_allow_html=True)


def render_sidebar():
    st.sidebar.markdown("""
    <div style="text-align: center; padding: 0.8rem 0;">
        <span style="font-size: 2.8rem;">🛡️</span>
        <h3 style="margin: 0.3rem 0 0 0; color: #f8fafc; font-size: 1.15rem;">Hybrid Cryptosystem</h3>
        <p style="color: #64748b; font-size: 0.78rem; margin: 0;">File Protection & Integrity Verification</p>
    </div>
    """, unsafe_allow_html=True)

    # Active User Status
    if "user" in st.session_state and st.session_state["user"] is not None:
        u = st.session_state["user"]
        st.sidebar.markdown(f"""
        <div style="background: #1e293b; border-radius: 8px; padding: 0.7rem; margin-bottom: 0.8rem; border: 1px solid #334155;">
            <div style="font-size: 0.72rem; color: #94a3b8; text-transform: uppercase;">Active User</div>
            <div style="font-weight: bold; color: #f8fafc; font-size: 0.95rem;">{u['fullname']}</div>
            <div style="font-size: 0.8rem; color: #38bdf8;">@{u['username']}</div>
        </div>
        """, unsafe_allow_html=True)
        if st.sidebar.button("🚪 Logout Session", use_container_width=True):
            st.session_state["user"] = None
            st.rerun()
    else:
        st.sidebar.markdown("""
        <div style="background: #111827; border-radius: 8px; padding: 0.7rem; margin-bottom: 0.8rem; border: 1px solid #1f2937;">
            <div style="font-size: 0.72rem; color: #f59e0b; font-weight: bold;">⚠️ NO USER SIGNED IN</div>
            <div style="font-size: 0.78rem; color: #94a3b8;">Log in under User Authentication to send or receive files.</div>
        </div>
        """, unsafe_allow_html=True)

    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🧭 Main Navigation")

    # Strict 6 Navigation Options
    navigation_options = [
        "🏠 Home / Dashboard",
        "🔐 User Authentication",
        "📤 Send File",
        "📥 Receive File",
        "🛡️ Security Monitoring",
        "📖 User Manual"
    ]

    selected_nav = st.sidebar.radio(
        "Go to page:",
        options=navigation_options,
        index=0
    )

    st.sidebar.markdown("---")
    st.sidebar.markdown("### ⚙️ Cryptographic Specifications")
    st.sidebar.markdown("""
    <div class="badge-container">
        <span class="crypto-badge badge-aes">AES-256-GCM</span>
        <span class="crypto-badge badge-rsa">RSA-2048-OAEP</span>
        <span class="crypto-badge badge-rsa">RSA-2048-PSS</span>
        <span class="crypto-badge badge-sha">SHA-256</span>
        <span class="crypto-badge badge-db">SQLite 3</span>
    </div>
    <div style="margin-top: 0.8rem; font-size: 0.75rem; color: #64748b;">
        <b>File Encryption:</b> AES-256-GCM<br>
        <b>Key Encapsulation:</b> RSA-2048-OAEP<br>
        <b>Digital Signatures:</b> RSA-2048-PSS<br>
        <b>Integrity Check:</b> SHA-256 Hash
    </div>
    """, unsafe_allow_html=True)

    lan_ip = get_lan_ip()
    st.sidebar.markdown(f"""
    <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 8px; padding: 0.65rem; margin-top: 1rem;">
        <div style="font-size: 0.72rem; color: #34d399; font-weight: bold; text-transform: uppercase;">🌐 Access Points</div>
        <div style="font-size: 0.76rem; color: #cbd5e1; margin-top: 4px; line-height: 1.4;">
            <b>Local:</b> <code>http://localhost:8501</code><br>
            <b>Wi-Fi/LAN:</b> <code>http://{lan_ip}:8501</code>
        </div>
        <div style="font-size: 0.68rem; color: #94a3b8; margin-top: 5px;">
            Open on other devices on your Wi-Fi or launch <code>start_public_server.bat</code> for worldwide access.
        </div>
    </div>
    """, unsafe_allow_html=True)

    return selected_nav


def render_home_dashboard():
    st.markdown("""
    <div style="background: linear-gradient(135deg, #1e293b, #0f172a); padding: 1.5rem; border-radius: 12px; border-left: 5px solid #3b82f6; margin-bottom: 1.5rem;">
        <h2 style="margin: 0; color: #f8fafc; font-size: 1.5rem;">🏠 System Overview & Workflow Dashboard</h2>
        <p style="margin: 0.3rem 0 0 0; color: #94a3b8; font-size: 0.95rem;">
            Securely Send Files &rarr; Receive Files &rarr; Verify Integrity &rarr; Detect Unauthorized Modifications &rarr; Notify Users.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Top-Level Telemetry Cards
    stats = database.get_system_stats()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Registered Accounts", stats["total_users"])
    c2.metric("Total Transfers", stats["total_transfers"])
    c3.metric("Verified Deliveries", stats["verified_count"])
    c4.metric("Attacks Detected", stats["attacks_detected"], delta="Protected" if stats["attacks_detected"] > 0 else None, delta_color="inverse")

    st.markdown("---")

    # Workflow Cards
    st.markdown("### 🔄 3-Step Operating Workflow")
    w1, w2, w3 = st.columns(3)

    with w1:
        st.markdown("""
        <div style="background: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 1.2rem; height: 100%;">
            <div style="font-size: 1.8rem; margin-bottom: 0.5rem;">🔐</div>
            <h4 style="color: #60a5fa; margin: 0 0 0.4rem 0;">1. Authenticate Identity</h4>
            <p style="color: #94a3b8; font-size: 0.88rem; line-height: 1.5;">
                Log in as a sender or recipient. Each user receives a 2048-bit RSA keypair, with passwords secured via PBKDF2-HMAC-SHA256.
            </p>
        </div>
        """, unsafe_allow_html=True)

    with w2:
        st.markdown("""
        <div style="background: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 1.2rem; height: 100%;">
            <div style="font-size: 1.8rem; margin-bottom: 0.5rem;">📤</div>
            <h4 style="color: #a78bfa; margin: 0 0 0.4rem 0;">2. Encrypt & Send</h4>
            <p style="color: #94a3b8; font-size: 0.88rem; line-height: 1.5;">
                Upload any file. The payload is encrypted with <b>AES-256-GCM</b>, the AES key is protected with <b>RSA-OAEP</b>, and signed with <b>RSA-PSS</b>.
            </p>
        </div>
        """, unsafe_allow_html=True)

    with w3:
        st.markdown("""
        <div style="background: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 1.2rem; height: 100%;">
            <div style="font-size: 1.8rem; margin-bottom: 0.5rem;">📥</div>
            <h4 style="color: #34d499; margin: 0 0 0.4rem 0;">3. Receive & Verify</h4>
            <p style="color: #94a3b8; font-size: 0.88rem; line-height: 1.5;">
                Recipient decrypts with their private key. If modified, a <b>RED SECURITY ALERT</b> blocks access; if clean, a <b>GREEN VERIFIED</b> notification grants download.
            </p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # Quick Testing Helper
    st.markdown("### ⚡ Quick Testing Instructions for Evaluators")
    st.markdown("""
    1. **Log in as Sender**: Go to **🔐 User Authentication** and click **👩 Alice (Sender)**.
    2. **Dispatch a File**: Go to **📤 Send File**, upload any file, select recipient **`@bob`**, and click **🚀 Encrypt and Send File**.
    3. **Verify as Recipient**: Switch user to **👨 Bob (Recipient)**, go to **📥 Receive File**, and click **🔑 Decrypt and Verify File**.  
       *Observe the **GREEN VERIFIED** alert and download the recovered file.*
    4. **Simulate an Attack**: Send another file from Alice to Bob, but select **`🔴 Simulate In-Transit Attack`**.  
       *Observe the recipient's screen triggering the prominent **RED SECURITY ALERT** with download permanently blocked.*
    5. **Read the Full Manual**: Open **📖 User Manual** from the sidebar for complete documentation.
    """)

    # Public & Remote Network Access Card
    lan_ip = get_lan_ip()
    with st.expander("🌐 How to Access this Web Application from Other Devices / Across the Internet", expanded=True):
        st.markdown(f"""
        <div style="background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 1.2rem;">
            <h4 style="margin: 0 0 0.8rem 0; color: #38bdf8;">🌍 Multi-Device & Public Internet Access</h4>
            <p style="color: #94a3b8; font-size: 0.9rem; line-height: 1.6;">
                This application is running on <b><code>0.0.0.0</code></b>, which allows anyone across your local network or the global internet to access the portal, register their own cryptographic keys, and exchange encrypted files with you.
            </p>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; margin-top: 1rem;">
                <div style="background: #1f2937; padding: 1rem; border-radius: 8px; border-left: 3px solid #3b82f6;">
                    <div style="color: #60a5fa; font-weight: bold; font-size: 0.9rem;">💻 Local Access</div>
                    <div style="color: #f1f5f9; font-family: monospace; font-size: 0.85rem; margin-top: 4px;">http://localhost:8501</div>
                    <div style="color: #94a3b8; font-size: 0.78rem; margin-top: 4px;">Use this on your current machine.</div>
                </div>
                <div style="background: #1f2937; padding: 1rem; border-radius: 8px; border-left: 3px solid #10b981;">
                    <div style="color: #34d399; font-weight: bold; font-size: 0.9rem;">📶 Wi-Fi / Local Network (LAN)</div>
                    <div style="color: #f1f5f9; font-family: monospace; font-size: 0.85rem; margin-top: 4px;">http://{lan_ip}:8501</div>
                    <div style="color: #94a3b8; font-size: 0.78rem; margin-top: 4px;">Share with any phone, tablet, or PC on your Wi-Fi!</div>
                </div>
                <div style="background: #1f2937; padding: 1rem; border-radius: 8px; border-left: 3px solid #8b5cf6;">
                    <div style="color: #a78bfa; font-weight: bold; font-size: 0.9rem;">🌐 Worldwide Public Tunnel</div>
                    <div style="color: #f1f5f9; font-family: monospace; font-size: 0.85rem; margin-top: 4px;">start_public_server.bat</div>
                    <div style="color: #94a3b8; font-size: 0.78rem; margin-top: 4px;">Run <code>python run_app.py --public</code> or double-click <code>start_public_server.bat</code> for an instant worldwide link.</div>
                </div>
            </div>
            <div style="margin-top: 1rem; color: #94a3b8; font-size: 0.82rem;">
                💡 <i>For complete step-by-step guidance on public sharing and free permanent 24/7 cloud hosting, open the <b>📖 User Manual</b> &rarr; <b>Section I</b>.</i>
            </div>
        </div>
        """, unsafe_allow_html=True)


def main():
    # Top Banner Header
    st.markdown("""
    <div class="main-header">
        <h1 class="main-title">🛡️ Innovative Hybrid Cryptographic File Protection and Integrity Verification</h1>
        <div class="sub-title">
            Enterprise-Grade Multi-Module Cryptosystem (AES-256-GCM • RSA-2048 • SHA-256 • SQLite)
        </div>
        <div class="badge-container">
            <span class="crypto-badge badge-aes">AES-256-GCM Encryption</span>
            <span class="crypto-badge badge-rsa">RSA-2048-OAEP Key Protection</span>
            <span class="crypto-badge badge-rsa">RSA-2048-PSS Digital Signatures</span>
            <span class="crypto-badge badge-sha">SHA-256 Integrity Verification</span>
            <span class="crypto-badge badge-db">SQLite Audit Logging</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Sidebar Navigation
    selected_nav = render_sidebar()

    # Route to Selected Page
    if selected_nav == "🏠 Home / Dashboard":
        render_home_dashboard()
    elif selected_nav == "🔐 User Authentication":
        render_module1()
    elif selected_nav == "📤 Send File":
        render_send_file()
    elif selected_nav == "📥 Receive File":
        render_receive_file()
    elif selected_nav == "🛡️ Security Monitoring":
        render_security_monitoring()
    elif selected_nav == "📖 User Manual":
        render_user_manual()


if __name__ == "__main__":
    main()
