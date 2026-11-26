"""
Security Monitoring and Audit Trail
Centralized security monitoring, immutable audit logging,
and cryptographic integrity verification tools.
"""

import streamlit as st
import pandas as pd
import crypto_engine
import database


def render_security_monitoring():
    st.markdown("""
    <div class="crypto-banner crypto-banner-sec">
        <h2>🛡️ Security Monitoring & Audit Trail</h2>
        <p>Real-time security telemetry, attack detection records, and immutable SQLite cryptographic audit logging.</p>
    </div>
    """, unsafe_allow_html=True)

    # Top-Level System Metrics
    stats = database.get_system_stats()
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Registered Users", stats["total_users"])
    m2.metric("Total Transfers", stats["total_transfers"])
    m3.metric("Verified Deliveries", stats["verified_count"])
    m4.metric("Attacks Detected", stats["attacks_detected"], delta=f"{stats['attacks_detected']} Alert(s)" if stats["attacks_detected"] > 0 else "None", delta_color="inverse")
    m5.metric("Pending Transfers", stats["pending_count"])

    st.markdown("---")

    sec_tab1, sec_tab2 = st.tabs(["📜 Security Event Logs", "🔬 Standalone Hash & Integrity Tools"])

    # ---------------- TAB 1: SECURITY AUDIT LOG ----------------
    with sec_tab1:
        st.subheader("Immutable Security Event Log")
        st.caption("All authentication events, encryption operations, deliveries, and attack detection alerts are permanently recorded:")

        logs = database.get_audit_logs(limit=200)
        if not logs:
            st.info("No security logs recorded yet.")
        else:
            df_logs = pd.DataFrame(logs)

            col_f1, col_f2 = st.columns(2)
            with col_f1:
                status_choices = list(df_logs["status"].unique())
                status_filter = st.multiselect("Filter by Status:", options=status_choices, default=status_choices)
            with col_f2:
                action_choices = list(df_logs["action"].unique())
                action_filter = st.multiselect("Filter by Action:", options=action_choices, default=action_choices)

            filtered_df = df_logs[df_logs["status"].isin(status_filter) & df_logs["action"].isin(action_filter)]
            st.dataframe(filtered_df, use_container_width=True)

            csv_bytes = filtered_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="⬇️ Export Security Logs (CSV)",
                data=csv_bytes,
                file_name="security_audit_logs.csv",
                mime="text/csv"
            )

    # ---------------- TAB 2: INTEGRITY TOOLS ----------------
    with sec_tab2:
        st.subheader("SHA-256 File Checksum Calculator & Avalanche Comparator")
        st.caption("Demonstrate how SHA-256 creates an irreversible 256-bit fingerprint and catches even a single-character modification:")

        c1, c2 = st.columns(2, gap="large")

        with c1:
            st.markdown("##### 1. Single File Hashing")
            test_file = st.file_uploader("Upload any file to calculate SHA-256:", key="sec_single_hash")
            if test_file:
                tb = test_file.getvalue()
                h = crypto_engine.compute_sha256(tb)
                st.markdown(f"""
                <div class="crypto-card-secondary">
                    <b>File:</b> {test_file.name} ({len(tb):,} bytes)<br>
                    <b>SHA-256 Digest:</b><br>
                    <code style="font-size: 0.88rem; word-break: break-all;">{h}</code>
                </div>
                """, unsafe_allow_html=True)

        with c2:
            st.markdown("##### 2. Differential Avalanche Effect Test")
            st.caption("Compare two files to see how changing 1 bit completely randomizes the resulting SHA-256 digest:")
            f1 = st.file_uploader("Upload File A:", key="sec_av_1")
            f2 = st.file_uploader("Upload File B (modified version):", key="sec_av_2")

            if f1 and f2:
                b1 = f1.getvalue()
                b2 = f2.getvalue()
                h1 = crypto_engine.compute_sha256(b1)
                h2 = crypto_engine.compute_sha256(b2)

                st.markdown(f"**Digest A:** `<code style='color:#38bdf8;word-break:break-all;'>{h1}</code>`", unsafe_allow_html=True)
                st.markdown(f"**Digest B:** `<code style='color:#f43f5e;word-break:break-all;'>{h2}</code>`", unsafe_allow_html=True)

                if h1 == h2:
                    st.success("✅ Files are 100% bit-identical!")
                else:
                    st.error("❌ Hashes differ! Unauthorized modification detected immediately by SHA-256.")


# Alias for backward compatibility
render_module3 = render_security_monitoring
