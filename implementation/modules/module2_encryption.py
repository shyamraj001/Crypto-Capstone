"""
Secure File Sending
Allows senders to upload, hybrid-encrypt (AES-256-GCM + RSA-OAEP),
digitally sign (RSA-PSS), and dispatch files to authorized recipients.
"""

import json
import base64
import streamlit as st
import pandas as pd
import crypto_engine
import database


def render_send_file():
    st.markdown("""
    <div style="background: linear-gradient(135deg, #1e1b4b, #0f172a); padding: 1.4rem; border-radius: 12px; border-left: 5px solid #8b5cf6; margin-bottom: 1.5rem;">
        <h2 style="margin: 0; color: #f8fafc; font-size: 1.5rem;">📤 Secure File Sending</h2>
        <p style="margin: 0.3rem 0 0 0; color: #cbd5e1; font-size: 0.95rem;">
            Encrypt files with <b>AES-256-GCM</b>, wrap the key with <b>RSA-OAEP</b>, fingerprint with <b>SHA-256</b>, and sign with <b>RSA-PSS</b>.
        </p>
    </div>
    """, unsafe_allow_html=True)

    if "user" not in st.session_state or st.session_state["user"] is None:
        st.warning("⚠️ Please log in under **User Authentication** before sending files.")
        return

    current_user = st.session_state["user"]

    send_col1, send_col2 = st.columns([1, 1], gap="large")

    with send_col1:
        st.subheader("1. Choose File to Send")
        uploaded_file = st.file_uploader(
            "Upload any file (Document, Image, Code, Archive, etc.):",
            type=None,
            key="send_file_uploader"
        )

        file_bytes = None
        filename = None
        file_sha256 = None

        if uploaded_file is not None:
            file_bytes = uploaded_file.getvalue()
            filename = uploaded_file.name
            file_sha256 = crypto_engine.compute_sha256(file_bytes)

            st.markdown(f"""
            <div style="background: #1e293b; padding: 0.9rem; border-radius: 8px; border: 1px solid #334155; margin-top: 0.8rem;">
                <b>Selected File:</b> {filename}<br>
                <b>File Size:</b> {len(file_bytes):,} bytes<br>
                <b>Calculated SHA-256 Checksum:</b><br>
                <code style="color: #10b981; font-size: 0.85rem; word-break: break-all;">{file_sha256}</code>
            </div>
            """, unsafe_allow_html=True)

    with send_col2:
        st.subheader("2. Select Recipient & Delivery Mode")
        all_users = database.get_all_users()
        other_users = [u for u in all_users if u["username"] != current_user["username"]]

        if not other_users:
            st.warning("No other users found. Please register a recipient under **User Authentication** first.")
            target_recipient = None
        else:
            default_index = 0
            for idx, u in enumerate(other_users):
                if u["username"] == "bob" and current_user["username"] != "bob":
                    default_index = idx
                    break

            target_recipient_username = st.selectbox(
                "Choose Authorized Recipient:",
                options=[u["username"] for u in other_users],
                index=default_index,
                format_func=lambda x: f"@{x} — {next(u['fullname'] for u in other_users if u['username'] == x)}"
            )
            target_recipient = next(u for u in other_users if u["username"] == target_recipient_username)

            st.markdown(f"""
            <div style="background: #111827; padding: 0.8rem; border-radius: 8px; border: 1px solid #1f2937; margin: 0.8rem 0; font-size: 0.85rem;">
                <b>Recipient:</b> {target_recipient['fullname']} (@{target_recipient['username']})<br>
                <b>Key Protection:</b> Recipient's 2048-bit RSA Public Key (RSA-OAEP)<br>
                <b>Sender Authentication:</b> Signed with @{current_user['username']}'s Private Key (RSA-PSS)
            </div>
            """, unsafe_allow_html=True)

            # Attack Simulation Option for Testing
            st.markdown("##### ⚡ Transmission Integrity Condition:")
            delivery_mode = st.radio(
                "Select Channel State for Testing:",
                [
                    "🟢 Normal Secure Delivery (Deliver Untampered)",
                    "🔴 Simulate In-Transit Attack (Alter 1 Byte in Transit to Test Attack Alert)"
                ],
                index=0,
                help="Select 'Simulate In-Transit Attack' to test how the recipient's system instantly detects unauthorized modifications."
            )

            if file_bytes and filename and target_recipient:
                if st.button("🚀 Encrypt and Send File", type="primary", use_container_width=True):
                    with st.spinner("Executing AES-256 encryption, RSA-OAEP key wrapping, and RSA-PSS digital signature..."):
                        # 1. Package creation
                        package = crypto_engine.create_hybrid_package(
                            file_bytes=file_bytes,
                            filename=filename,
                            sender_username=current_user["username"],
                            sender_private_pem=current_user["private_key"],
                            recipient_username=target_recipient["username"],
                            recipient_public_pem=target_recipient["rsa_public_key"]
                        )

                        # 2. Check if simulated attack requested
                        is_simulated_attack = "Simulate In-Transit Attack" in delivery_mode
                        if is_simulated_attack:
                            package = crypto_engine.tamper_package_ciphertext(package)

                        pkg_json_str = json.dumps(package)
                        initial_status = "PENDING"

                        transfer_id = database.create_transfer_record(
                            sender_id=current_user["id"],
                            sender_username=current_user["username"],
                            recipient_id=target_recipient["id"],
                            recipient_username=target_recipient["username"],
                            original_filename=filename,
                            file_size=len(file_bytes),
                            package_json=pkg_json_str,
                            sha256_hash=file_sha256,
                            initial_status=initial_status
                        )

                        if is_simulated_attack:
                            st.warning(f"⚠️ Transfer #{transfer_id} dispatched to @{target_recipient['username']} with **Simulated In-Transit Tampering**! When the recipient attempts to recover it, an ATTACK ALERT will trigger.")
                        else:
                            st.success(f"✅ Transfer #{transfer_id} successfully encrypted and dispatched to @{target_recipient['username']}!")

                        st.rerun()

    # Outbox Section
    st.markdown("---")
    st.markdown(f"### 📋 Sent Transfers (Outbox of @{current_user['username']})")
    st.caption("Track the real-time status of files you sent. The status updates automatically when the recipient verifies or detects tampering.")

    sent_files = database.get_sent_transfers(current_user["id"])
    if not sent_files:
        st.info("You haven't sent any files yet. Use the form above to send your first file.")
    else:
        outbox_rows = []
        for s in sent_files:
            # Visual status badges
            status_text = s["status"]
            if status_text == "VERIFIED":
                badge = "✅ VERIFIED"
            elif status_text == "ATTACK DETECTED":
                badge = "🚨 ATTACK DETECTED"
            elif status_text == "RECEIVED":
                badge = "📥 RECEIVED"
            else:
                badge = "⏳ PENDING"

            outbox_rows.append({
                "Transfer ID": s["id"],
                "Recipient": f"@{s['recipient_username']} ({s['recipient_fullname']})",
                "File Name": s["original_filename"],
                "Size": f"{s['file_size']:,} bytes",
                "SHA-256 Fingerprint": f"{s['sha256_hash'][:18]}...",
                "Transfer Status": badge,
                "Sent Time": s["created_at"]
            })

        st.dataframe(pd.DataFrame(outbox_rows), use_container_width=True)

        # In-Transit Tamper Test Trigger for Outbox
        with st.expander("🛠️ Outbox Attack Simulation Tool (Intercept Pending File)", expanded=False):
            st.caption("You can simulate intercepting any sent file in transit to corrupt its ciphertext before the recipient opens it:")
            pending_sent = [s for s in sent_files if s["status"] == "PENDING"]
            if not pending_sent:
                st.info("No PENDING transfers available to intercept.")
            else:
                intercept_col1, intercept_col2 = st.columns([3, 1])
                target_intercept_id = intercept_col1.selectbox(
                    "Select Pending Transfer to Intercept:",
                    options=[s["id"] for s in pending_sent],
                    format_func=lambda x: next(f"#{s['id']}: {s['original_filename']} sent to @{s['recipient_username']}" for s in pending_sent if s["id"] == x)
                )
                with intercept_col2:
                    if st.button("💥 Intercept & Corrupt", use_container_width=True):
                        ok = database.simulate_in_transit_attack(target_intercept_id, current_user["username"])
                        if ok:
                            st.error(f"Transfer #{target_intercept_id} was intercepted! Status changed to ATTACK DETECTED.")
                            st.rerun()


# Alias for backward compatibility
render_module2 = render_send_file
