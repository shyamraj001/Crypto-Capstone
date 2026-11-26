"""
Secure File Receiving and Attack Detection
Allows recipients to view incoming files, decrypt with RSA-OAEP & AES-256-GCM,
verify RSA-PSS signatures and SHA-256 integrity, trigger prominent RED SECURITY ALERTS on attack,
and grant readable access and downloads only when verified.
"""

import json
import streamlit as st
import pandas as pd
import crypto_engine
import database


def render_receive_file():
    st.markdown("""
    <div class="crypto-banner crypto-banner-recv">
        <h2>📥 Secure File Receiving & Attack Detection</h2>
        <p>Decrypt incoming packages, mathematically verify sender authenticity and SHA-256 integrity, and detect in-transit attacks.</p>
    </div>
    """, unsafe_allow_html=True)

    if "user" not in st.session_state or st.session_state["user"] is None:
        st.warning("⚠️ Please log in under **User Authentication** to view your received files.")
        return

    current_user = st.session_state["user"]

    # 1. Fetch incoming files for recipient
    incoming_transfers = database.get_received_transfers(current_user["id"])

    st.subheader(f"📬 Incoming Files for @{current_user['username']}")

    if not incoming_transfers:
        st.info(f"No incoming files for @{current_user['username']} yet. Log in as another user (e.g. Alice) to send a file to @{current_user['username']}.")
        return

    # Incoming Files Overview Table
    inbox_table = []
    for t in incoming_transfers:
        status_text = t["status"]
        if status_text == "VERIFIED":
            badge = "✅ VERIFIED"
        elif status_text == "ATTACK DETECTED":
            badge = "🚨 ATTACK DETECTED"
        elif status_text == "RECEIVED":
            badge = "📥 RECEIVED"
        else:
            badge = "⏳ PENDING"

        inbox_table.append({
            "Transfer ID": t["id"],
            "Sender": f"@{t['sender_username']} ({t['sender_fullname']})",
            "File Name": t["original_filename"],
            "Size": f"{t['file_size']:,} bytes",
            "SHA-256 Digest": f"{t['sha256_hash'][:18]}...",
            "Status": badge,
            "Received Time": t["created_at"]
        })

    st.dataframe(pd.DataFrame(inbox_table), use_container_width=True)

    st.markdown("---")
    st.subheader("🔑 File Decryption & Integrity Verification")
    st.caption("Select an incoming package below to unwrap the AES session key, decrypt the content, and verify all cryptographic proofs:")

    sel_col1, sel_col2 = st.columns([2, 1])

    with sel_col1:
        selected_transfer_id = st.selectbox(
            "Select an Incoming File:",
            options=[t["id"] for t in incoming_transfers],
            format_func=lambda x: next(f"Transfer #{t['id']}: {t['original_filename']} from @{t['sender_username']} [{t['status']}]" for t in incoming_transfers if t["id"] == x)
        )

    chosen_transfer = next(t for t in incoming_transfers if t["id"] == selected_transfer_id)
    pkg_dict = json.loads(chosen_transfer["package_json"])

    with sel_col2:
        st.markdown(f"""
        <div class="crypto-card-secondary" style="margin-top: 1.5rem;">
            <b>Sender:</b> @{chosen_transfer['sender_username']}<br>
            <b>Target File:</b> {chosen_transfer['original_filename']}<br>
            <b>Current Status:</b> <code>{chosen_transfer['status']}</code>
        </div>
        """, unsafe_allow_html=True)

    if st.button("🔑 Decrypt and Verify File", type="primary", use_container_width=True):
        with st.spinner("Decrypting AES session key with RSA-OAEP, verifying AES-GCM tag, checking SHA-256 hash and RSA-PSS signature..."):
            sender_pub_key = chosen_transfer["sender_public_key"]
            recipient_priv_key = current_user["private_key"]

            # Decrypt & Verify
            result = crypto_engine.decrypt_and_verify_hybrid_package(
                package=pkg_dict,
                recipient_private_pem=recipient_priv_key,
                sender_public_pem=sender_pub_key
            )

            # =========================================================================
            # CASE 1: ATTACK / MODIFICATION DETECTED -> PROMINENT RED SECURITY ALERT
            # =========================================================================
            if not result["success"]:
                st.markdown(f"""
                <div class="crypto-alert-red">
                    <h2>🚨 RED SECURITY ALERT: FILE INTEGRITY VERIFICATION FAILED!</h2>
                    <h4>POTENTIAL ATTACK DETECTED: UNAUTHORIZED FILE MODIFICATION DETECTED IN TRANSIT!</h4>
                    <p style="margin: 1rem 0; font-size: 1rem; line-height: 1.6;">
                        <b>Security Warning for Recipient:</b> The encrypted package for <code>{chosen_transfer['original_filename']}</code> has failed mathematical verification!
                        The data received does not match the sender's original authentic payload.
                    </p>
                    <div class="crypto-alert-red-inner">
                        <b>Cryptographic Reason for Rejection:</b><br>
                        <span style="font-family: monospace; font-size: 0.95rem;">{result['error_message']}</span>
                    </div>
                    <ul style="margin: 0.8rem 0 0 0; padding-left: 1.4rem; font-size: 0.92rem;">
                        <li><b>Integrity Status:</b> FAILED — 1 or more bytes were modified or corrupted during transit.</li>
                        <li><b>Sender Authentication:</b> REJECTED — Authentic origin cannot be mathematically confirmed.</li>
                        <li><b>Security Lockdown:</b> <u>File download and plaintext preview are permanently blocked</u> to protect your system from executing or opening malicious or corrupted payloads.</li>
                    </ul>
                </div>
                """, unsafe_allow_html=True)

                # Update database status to ATTACK DETECTED
                database.update_transfer_status(
                    transfer_id=chosen_transfer["id"],
                    new_status="ATTACK DETECTED",
                    user_id=current_user["id"],
                    username=current_user["username"],
                    details=f"Attack detected for transfer #{chosen_transfer['id']} ({chosen_transfer['original_filename']}): {result['error_message']}"
                )

            # =========================================================================
            # CASE 2: VERIFICATION SUCCESSFUL -> PROMINENT GREEN VERIFIED NOTIFICATION
            # =========================================================================
            else:
                st.markdown(f"""
                <div class="crypto-alert-green">
                    <h2>✅ GREEN VERIFIED: FILE AUTHENTIC & UNTAMPERED!</h2>
                    <h4>SUCCESSFUL VERIFICATION: SENDER AUTHENTICATED & INTEGRITY CONFIRMED</h4>
                    <p style="margin: 1rem 0; font-size: 1rem; line-height: 1.6;">
                        The file safely passed all cryptographic verification tests with zero modifications in transit.
                    </p>
                    <ul style="margin: 0.8rem 0 0 0; padding-left: 1.4rem; font-size: 0.92rem;">
                        <li><b>Sender Identity Confirmed:</b> Digitally signed by <b>@{chosen_transfer['sender_username']}</b> ({chosen_transfer['sender_fullname']}) using <b>RSA-2048-PSS</b>.</li>
                        <li><b>SHA-256 Digest Confirmed:</b> Calculated hash matches expected checksum: <code>{result['calculated_sha256']}</code></li>
                        <li><b>Confidentiality Protected:</b> 256-bit AES session key successfully decrypted using your private key (<b>RSA-OAEP</b>).</li>
                        <li><b>Authentication Tag:</b> <b>AES-256-GCM</b> 128-bit MAC tag verified with zero tampering.</li>
                    </ul>
                </div>
                """, unsafe_allow_html=True)

                # Update database status to VERIFIED
                database.update_transfer_status(
                    transfer_id=chosen_transfer["id"],
                    new_status="VERIFIED",
                    user_id=current_user["id"],
                    username=current_user["username"],
                    details=f"Successfully verified authentic file #{chosen_transfer['id']} ({chosen_transfer['original_filename']}) from @{chosen_transfer['sender_username']}"
                )

                st.markdown("### 📖 Recovered File (Readable Format)")

                # If text/document readable preview
                try:
                    text_content = result["plaintext_bytes"].decode('utf-8')
                    st.markdown("##### 📄 On-Screen Plaintext Preview:")
                    st.text_area(
                        label="Decrypted File Contents:",
                        value=text_content,
                        height=160,
                        disabled=True
                    )
                except UnicodeDecodeError:
                    st.info("ℹ️ This file is in a binary format (e.g., PDF, image, spreadsheet, or archive). Click the download button below to save and open it in its native application.")

                # Direct Download Button
                st.download_button(
                    label=f"⬇️ Download Original '{chosen_transfer['original_filename']}'",
                    data=result["plaintext_bytes"],
                    file_name=chosen_transfer["original_filename"],
                    mime="application/octet-stream",
                    use_container_width=True,
                    type="primary"
                )


# Alias for backward compatibility
render_module4 = render_receive_file
