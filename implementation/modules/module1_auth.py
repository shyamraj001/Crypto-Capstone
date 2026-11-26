"""
User Authentication
Secure user registration, login, and cryptographic identity provisioning.
"""

import streamlit as st
import pandas as pd
import database
import crypto_engine


def render_module1():
    st.markdown("""
    <div class="crypto-banner crypto-banner-auth">
        <h2>🔐 User Authentication & Identity Management</h2>
        <p>Secure multi-user login with PBKDF2-HMAC-SHA256 password hashing and automated 2048-bit RSA keypair generation.</p>
    </div>
    """, unsafe_allow_html=True)

    if "user" not in st.session_state or st.session_state["user"] is None:
        render_login_and_registration()
    else:
        render_user_profile()


def render_login_and_registration():
    col1, col2 = st.columns([1, 1], gap="large")

    with col1:
        st.subheader("🔑 User Login")
        st.caption("Sign in with your username and password:")
        with st.form("login_form"):
            login_username = st.text_input("Username", placeholder="e.g. alice, bob, or charlie").strip().lower()
            login_password = st.text_input("Password", type="password", placeholder="Enter your password")
            submit_login = st.form_submit_button("🔓 Log In", use_container_width=True, type="primary")

            if submit_login:
                if not login_username or not login_password:
                    st.error("Please enter both username and password.")
                else:
                    success, user_data, msg = database.authenticate_user(login_username, login_password)
                    if success:
                        st.session_state["user"] = user_data
                        st.success(f"Welcome, {user_data['fullname']}!")
                        st.rerun()
                    else:
                        st.error(msg)

        # Quick Demo Accounts
        st.markdown("---")
        st.markdown("##### ⚡ Quick Persona Switcher (For Testing)")
        st.caption("Click any persona below to quickly test sending and receiving files:")
        demo_cols = st.columns(3)
        with demo_cols[0]:
            if st.button("👩 Alice (Sender)", use_container_width=True):
                success, user_data, _ = database.authenticate_user("alice", "Alice@123")
                if success:
                    st.session_state["user"] = user_data
                    st.rerun()
        with demo_cols[1]:
            if st.button("👨 Bob (Recipient)", use_container_width=True):
                success, user_data, _ = database.authenticate_user("bob", "Bob@123")
                if success:
                    st.session_state["user"] = user_data
                    st.rerun()
        with demo_cols[2]:
            if st.button("🧔 Charlie (Auditor)", use_container_width=True):
                success, user_data, _ = database.authenticate_user("charlie", "Charlie@123")
                if success:
                    st.session_state["user"] = user_data
                    st.rerun()

    with col2:
        st.subheader("📝 Register New Account")
        st.caption("A unique 2048-bit RSA keypair will be generated automatically for your identity.")
        with st.form("register_form"):
            reg_username = st.text_input("Choose Username", placeholder="e.g. john, maria").strip().lower()
            reg_fullname = st.text_input("Full Name", placeholder="e.g. John Doe")
            reg_email = st.text_input("Email Address", placeholder="e.g. john@example.com")
            reg_password = st.text_input("Password", type="password", placeholder="Enter a secure password")
            submit_reg = st.form_submit_button("✨ Register & Generate RSA Keypair", use_container_width=True)

            if submit_reg:
                if not reg_username or not reg_password or not reg_fullname:
                    st.error("Username, Full Name, and Password are required.")
                else:
                    with st.spinner("Generating 2048-bit RSA keys and securing credentials..."):
                        success, msg, priv_pem = database.register_user(reg_username, reg_fullname, reg_email, reg_password)
                        if success:
                            st.success(msg)
                            st.info("You can now log in using your credentials on the left.")
                        else:
                            st.error(msg)


def render_user_profile():
    user = st.session_state["user"]

    # Header with User Status
    status_col1, status_col2 = st.columns([3, 1])
    with status_col1:
        st.markdown(f"""
        <div class="crypto-card-secondary" style="display: flex; align-items: center; gap: 15px; margin-bottom: 1rem;">
            <div style="background: #2563eb; color: white; width: 48px; height: 48px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 1.3rem; flex-shrink: 0;">
                {user['username'][0].upper()}
            </div>
            <div>
                <h3 style="margin: 0; font-size: 1.15rem;">{user['fullname']} (<span style="color: #2563eb;">@{user['username']}</span>)</h3>
                <span style="opacity: 0.8; font-size: 0.85rem;">✉️ {user['email']} &nbsp;|&nbsp; 🔐 2048-bit RSA Keys Loaded</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
    with status_col2:
        if st.button("🚪 Log Out", use_container_width=True):
            st.session_state["user"] = None
            st.rerun()

    tab1, tab2 = st.tabs(["🔑 Your Cryptographic Keys", "👥 Registered Users Directory"])

    with tab1:
        st.markdown("#### Your RSA-2048 Cryptographic Keys")
        st.caption("Your public key is published so senders can encrypt session keys for you; your private key is kept confidential to decrypt incoming files.")

        k1, k2 = st.columns(2)
        with k1:
            st.markdown("##### 🌐 RSA Public Key")
            st.text_area("Public Key (Shareable)", value=user["public_key"], height=200, disabled=True)
            st.download_button(
                label="⬇️ Download Public Key (.pem)",
                data=user["public_key"],
                file_name=f"{user['username']}_public_key.pem",
                mime="application/x-pem-file",
                use_container_width=True
            )
        with k2:
            st.markdown("##### 🔒 RSA Private Key")
            st.text_area("Private Key (Confidential)", value=user["private_key"], height=200, disabled=True)
            st.download_button(
                label="⬇️ Download Private Key (.pem)",
                data=user["private_key"],
                file_name=f"{user['username']}_private_key.pem",
                mime="application/x-pem-file",
                use_container_width=True
            )

    with tab2:
        st.markdown("#### Registered System Users")
        st.caption("These are the authorized users you can send encrypted files to:")
        all_users = database.get_all_users()
        user_rows = []
        for u in all_users:
            user_rows.append({
                "Username": f"@{u['username']}",
                "Full Name": u["fullname"],
                "Email": u["email"],
                "Key Type": "RSA-2048",
                "Created At": u["created_at"]
            })
        st.dataframe(pd.DataFrame(user_rows), use_container_width=True)
