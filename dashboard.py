import streamlit as st
import pandas as pd
import time
from auth import (authenticate, init_default_admin, get_all_users, create_user,
                  delete_user, log_audit, hash_password, add_monitored_path,
                  remove_monitored_path, get_monitored_paths, init_config_tables,
                  clear_force_password_change, validate_password_policy)

from secure_chain import verify_chain
from report import generate_report_bytes
from selfwatch import get_self_integrity_status, check_self_integrity
from datetime import datetime
import altair as alt

# Use the shared connection factory from utils.py — single source of truth
# for WAL mode, busy_timeout, retry, and cache pragmas.
from utils import db_connect as _connect, init_all_tables

DB_PATH = "fim.db"


st.set_page_config(page_title="FIM Dashboard", layout="wide", initial_sidebar_state="expanded")

if 'init_done' not in st.session_state:
    init_all_tables()
    init_default_admin()
    init_config_tables()
    st.session_state.init_done = True

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None
if 'force_password_change' not in st.session_state:
    st.session_state.force_password_change = False
if 'last_activity' not in st.session_state:
    st.session_state.last_activity = None

# ── Session timeout ───────────────────────────────────────────────────────────
SESSION_TIMEOUT_MINUTES = 30


def _is_session_expired():
    """True if the user has been idle longer than SESSION_TIMEOUT_MINUTES."""
    if not st.session_state.logged_in:
        return False
    last = st.session_state.get("last_activity")
    if last is None:
        return False
    elapsed = (datetime.now() - last).total_seconds()
    return elapsed > SESSION_TIMEOUT_MINUTES * 60


def _force_logout(reason="Session expired"):
    """Clear session state and audit the forced logout."""
    if st.session_state.get("username"):
        try:
            log_audit(st.session_state.username, "LOGOUT_TIMEOUT",
                      reason, success=1)
        except Exception:
            pass
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None
    st.session_state.force_password_change = False
    st.session_state.last_activity = None


def show_login():
    st.title("🛡️ FIM Dashboard - Login")
    st.caption("Real-Time File Integrity and Security Monitoring")

    # Constrain the form to the middle 1/3 of the page so it doesn't
    # stretch across a wide monitor.  Previous [1, 2, 1] gave the form
    # 50% of the viewport which looked excessive.
    col1, col2, col3 = st.columns([2, 3, 2])
    with col2:
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Log In", use_container_width=True)
            
            if submit:
                if username and password:
                    success, role = authenticate(username, password)
                    if success:
                        # `role` is now a dict {"role": str, "force_change": bool}
                        # returned by the new auth.authenticate().  No more
                        # hardcoded plaintext password comparison.
                        st.session_state.logged_in = True
                        st.session_state.username = username
                        st.session_state.role = role["role"]
                        st.session_state.force_password_change = role["force_change"]
                        # Stamp last activity now so the session-timeout
                        # check has a starting point.
                        st.session_state.last_activity = datetime.now()
                        st.rerun()
                    elif role == "LOCKED":
                        st.error(
                            "⛔ Account locked — too many failed attempts. "
                            "Try again in 15 minutes."
                        )
                    else:
                        st.error("Invalid username or password")
                else:
                    st.warning("Please enter both username and password")


def show_force_password_change():
    st.title("🔐 Password Change Required")
    st.warning("You are using the default password. You must change it before continuing.")

    with st.form("change_password_form"):
        new_password = st.text_input(
            "New Password (min 10 chars, must contain a letter and a digit)",
            type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        submit = st.form_submit_button("Change Password")

        if submit:
            # Use the same policy validator as auth.create_user so the
            # rules can never drift between the two screens.
            policy_ok, policy_msg = validate_password_policy(new_password)
            if new_password != confirm_password:
                st.error("Passwords do not match")
            elif not policy_ok:
                st.error(policy_msg)
            else:
                conn = _connect()
                c = conn.cursor()
                new_hash = hash_password(new_password)
                c.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                          (new_hash, st.session_state.username))
                conn.commit()
                conn.close()
                # Also clear the force_password_change DB flag so the user
                # isn't prompted again on their next login.
                clear_force_password_change(st.session_state.username)
                log_audit(st.session_state.username, "PASSWORD_CHANGED", success=1)
                st.session_state.force_password_change = False
                st.success("Password changed. Continuing to dashboard...")
                time.sleep(2)
                st.rerun()


def show_dashboard():
    with st.sidebar:
        st.title("🛡️ FIM System")
        st.write(f"**User:** {st.session_state.username}")
        st.write(f"**Role:** {st.session_state.role}")
        # Self-integrity status pill in sidebar
        try:
            _si_ok, _si_v = check_self_integrity()
            if _si_ok:
                st.success("🛡️ Self-Integrity OK")
            else:
                st.error(f"⚠️ Self-Integrity: {len(_si_v)} violation(s)")
        except Exception:
            st.warning("Self-Integrity: unavailable")
        st.divider()
        
        if st.session_state.role == "admin":
            page = st.radio("Navigation", ["Dashboard", "Alerts", "Reports", "Configuration", "User Management", "Log Report", "Chain Verify", "Self-Integrity"])
        else:
            page = st.radio("Navigation", ["Dashboard", "Alerts", "Reports", "Log Report", "Chain Verify"])
        
        st.divider()
        if st.button("Logout", use_container_width=True):
            log_audit(st.session_state.username, "LOGOUT", success=1)
            st.session_state.logged_in = False
            st.session_state.username = None
            st.session_state.role = None
            st.rerun()
    
    if page == "Dashboard":
        show_main_dashboard()
    elif page == "Alerts":
        show_alerts_page()
    elif page == "Configuration":
        show_configuration()
    elif page == "User Management":
        show_user_management()
    elif page == "Log Report":
        show_audit_log()
    elif page == "Reports":
        show_reports()
    elif page == "Chain Verify":
        show_chain_verify()
    elif page == "Self-Integrity":
        show_self_integrity()


def get_baseline_files():
    conn = _connect()
    try:
        df = pd.read_sql_query("SELECT path, hash, size FROM baseline", conn)
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df


def get_alerts():
    conn = _connect()
    try:
        df = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC LIMIT 200", conn)
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df


def get_alert_counts():
    
    counts = {"total": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    conn = _connect()
    try:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM alerts")
        counts["total"] = c.fetchone()[0]
        c.execute(
            "SELECT severity, COUNT(*) FROM alerts "
            "WHERE severity IN ('HIGH', 'MEDIUM', 'LOW') "
            "GROUP BY severity"
        )
        for sev, n in c.fetchall():
            counts[sev] = n
    except Exception:
        pass
    finally:
        conn.close()
    return counts


def get_severity_trend(window_hours=24):
   
    conn = _connect()
    bucket = (
        "strftime('%Y-%m-%d %H:00', timestamp)"
        if window_hours <= 48
        else "strftime('%Y-%m-%d', timestamp)"
    )
    query = f"""
        SELECT
            {bucket}   AS period,
            severity,
            COUNT(*)    AS count
        FROM alerts
        WHERE timestamp >= datetime('now', '-{window_hours} hours')
          AND severity IN ('HIGH', 'MEDIUM', 'LOW')
        GROUP BY period, severity
        ORDER BY period
    """
    try:
        df = pd.read_sql_query(query, conn)
    except Exception:
        df = pd.DataFrame()
    conn.close()

    if df.empty:
        return pd.DataFrame(columns=['period', 'HIGH', 'MEDIUM', 'LOW'])

    pivot = df.pivot_table(
        index='period', columns='severity', values='count', fill_value=0
    ).reset_index()
    pivot.columns.name = None
    for col in ['HIGH', 'MEDIUM', 'LOW']:
        if col not in pivot.columns:
            pivot[col] = 0
    return pivot[['period', 'HIGH', 'MEDIUM', 'LOW']]


def show_main_dashboard():
    # ── Header row: title + refresh controls ──────────────────────────────
    hcol1, hcol2 = st.columns([3, 1])
    with hcol1:
        st.title("🛡️ Real-Time File Integrity Monitor")
        st.caption("Layered detection: hash baselines, tamper-evident audit chain, "
                   "and self-integrity monitoring")
    with hcol2:
        st.write("")
        st.write("")
        auto_refresh = st.toggle(
            "Auto-refresh",
            value=st.session_state.get("auto_refresh", True),
            help="Automatically reload the dashboard at a fixed interval",
        )
        st.session_state["auto_refresh"] = auto_refresh
        _REFRESH_OPTIONS = [15, 30, 60, 120]
        # Clamp stored value to a valid option — guards against the old
        # default of 10 which is not in the list and causes ValueError.
        _stored = st.session_state.get("refresh_interval", 30)
        _safe_default = _stored if _stored in _REFRESH_OPTIONS else 30
        refresh_interval = 30  # fallback when auto-refresh is off
        if auto_refresh:
            refresh_interval = st.select_slider(
                "Interval", options=_REFRESH_OPTIONS,
                value=_safe_default,
                format_func=lambda v: f"{v}s",
            )
            st.session_state["refresh_interval"] = refresh_interval
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()

    # ── KPI metrics ────────────────────────────────────────────────────────
    # KPI tiles must reflect the FUL alerts table, not the LIMIT-200
    # dataframe used to render the table below.  get_alert_counts() runs
    # real COUNT(*) queries against the database; on a system with >200
    # alerts the previous len(alerts_df) approach silently undercounted.
    baseline_df = get_baseline_files()
    alerts_df   = get_alerts()
    counts      = get_alert_counts()

    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        st.metric("Files Monitored", len(baseline_df))
    with k2:
        st.metric("Total Alerts", counts["total"])
    with k3:
        st.metric("🔴 HIGH", counts["HIGH"])
    with k4:
        st.metric("🟡 MEDIUM", counts["MEDIUM"])
    with k5:
        st.metric("🟢 LOW", counts["LOW"])

    st.divider()

    # ── Charts row ─────────────────────────────────────────────────────────
    chart_col1, chart_col2 = st.columns([3, 2])

    with chart_col1:
        st.subheader("Alert Severity Trend")
        window_options = {
            "Last 24 hours": 24,
            "Last 48 hours": 48,
            "Last 7 days":   168,
            "Last 30 days":  720,
        }
        selected_window = st.selectbox(
            "Time window", list(window_options.keys()),
            label_visibility="collapsed",
            key="trend_window",
        )
        trend_df = get_severity_trend(window_options[selected_window])
        has_data = (
            not trend_df.empty
            and trend_df[['HIGH', 'MEDIUM', 'LOW']].values.sum() > 0
        )
        if has_data:
            trend_long = trend_df.melt(
                id_vars='period',
                value_vars=['HIGH', 'MEDIUM', 'LOW'],
                var_name='severity',
                value_name='count',
            )
            trend_long['period'] = pd.to_datetime(trend_long['period'])
            sev_order = ['HIGH', 'MEDIUM', 'LOW']
            chart = (
                alt.Chart(trend_long)
                .mark_area(opacity=0.80, interpolate='monotone')
                .encode(
                    x=alt.X('period:T', title='Time',
                             axis=alt.Axis(labelAngle=-35, format='%b %d %H:%M')),
                    y=alt.Y('count:Q', stack=True, title='Alert Count'),
                    color=alt.Color(
                        'severity:N',
                        sort=sev_order,
                        scale=alt.Scale(
                            domain=sev_order,
                            range=['#DC2626', '#D97706', '#16A34A'],
                        ),
                        legend=alt.Legend(title='Severity'),
                    ),
                    order=alt.Order('severity:N', sort='ascending'),
                    tooltip=[
                        alt.Tooltip('period:T',   title='Time', format='%Y-%m-%d %H:%M'),
                        alt.Tooltip('severity:N', title='Severity'),
                        alt.Tooltip('count:Q',    title='Count'),
                    ],
                )
                .properties(height=280)
                .configure_view(strokeWidth=0)
            )
            st.altair_chart(chart, use_container_width=True)
        else:
            st.info(
                "No alerts in this time window yet. "
                "Start monitor.py, configure a path, and modify a file to generate events."
            )

    with chart_col2:
        st.subheader("Alerts by MITRE ATT&CK")
        if not alerts_df.empty and 'mitre_technique' in alerts_df.columns:
            mitre_df = (
                alerts_df.groupby('mitre_technique')
                .size()
                .reset_index(name='count')
                .sort_values('count', ascending=False)
            )
            st.bar_chart(mitre_df.set_index('mitre_technique'), color="#3B82F6")
        else:
            st.info("No data yet.")

    st.divider()

    # ── Recent alerts table ────────────────────────────────────────────────
    st.subheader("Recent Alerts (Last 10)")
    if not alerts_df.empty:
        recent = alerts_df.head(10)[
            ['timestamp', 'event_type', 'file_path', 'severity', 'mitre_technique']
        ]
        st.dataframe(recent, use_container_width=True, hide_index=True)
    else:
        st.info("No alerts yet. Start monitor.py and configure a monitored path to begin.")

    # ── Footer: last updated + auto-refresh trigger ────────────────────────
    st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if auto_refresh:
        time.sleep(refresh_interval)
        st.rerun()


def show_alerts_page():
    st.title("📋 All Alerts")

    # ── Discord delivery status banner ──
    # Surfaces pending offline-queue depth so the operator knows when
    # Discord is behind.  Quiet when everything is delivered.
    try:
        from alerts import queue_stats
        pending, oldest = queue_stats()
        if pending > 0:
            st.warning(
                f"📡  **Discord offline queue:** {pending} alert(s) pending "
                f"replay (oldest queued at {oldest}). They will be sent "
                "automatically when Discord becomes reachable."
            )
    except Exception:
        pass

    alerts_df = get_alerts()
    
    if alerts_df.empty:
        st.info("No alerts yet.")
        return
    
    col1, col2, col3 = st.columns(3)
    with col1:
        event_filter = st.selectbox("Event Type", ["All"] + list(alerts_df['event_type'].unique()))
    with col2:
        severity_filter = st.selectbox("Severity", ["All"] + list(alerts_df['severity'].unique()))
    with col3:
        search = st.text_input("Search file path")
    
    filtered = alerts_df.copy()
    if event_filter != "All":
        filtered = filtered[filtered['event_type'] == event_filter]
    if severity_filter != "All":
        filtered = filtered[filtered['severity'] == severity_filter]
    if search:
        filtered = filtered[filtered['file_path'].str.contains(search, case=False, na=False)]
    
    st.write(f"Showing {len(filtered)} of {len(alerts_df)} alerts")
    st.dataframe(filtered, use_container_width=True, hide_index=True)
    
    csv = filtered.to_csv(index=False).encode('utf-8')
    st.download_button("Download CSV", csv, "alerts.csv", "text/csv")


def show_configuration():
    if st.session_state.role != "admin":
        st.error("Access denied. Admin only.")
        return

    st.title("⚙️ System Configuration")

    st.subheader("Currently Monitored Paths")
    paths = get_monitored_paths()
    if paths:
        paths_df = pd.DataFrame(paths, columns=['ID', 'Path', 'Enabled', 'Added By', 'Added At'])
        st.dataframe(paths_df, use_container_width=True, hide_index=True)
    else:
        st.info("No monitored paths configured.")

    st.divider()
    st.subheader("Add Monitored Path")
    with st.form("add_path_form"):
        new_path = st.text_input("Folder path (e.g., D:\\FIM_Project123\\Web_Server_Files)")
        if st.form_submit_button("Add Path"):
            if new_path:
                success, msg = add_monitored_path(new_path, st.session_state.username)
                if success:
                    st.success(msg)
                    # monitor.py reconciles its watch list against the
                    # database every RELOAD_INTERVAL seconds (default 10),
                    # so new paths are picked up automatically.
                    st.info("New paths are picked up automatically within "
                            "10 seconds — no monitor restart required.")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error(msg)

    st.subheader("Remove Path")
    if paths:
        path_options = [p[1] for p in paths]
        path_to_remove = st.selectbox("Select path to remove", path_options)
        if st.button("Remove Path", type="primary"):
            remove_monitored_path(path_to_remove, st.session_state.username)
            st.success("Path removed")
            time.sleep(1)
            st.rerun()

    st.divider()
    with st.expander("ℹ️ Default severity by event type", expanded=False):
        st.markdown("""
| Event        | Default severity | MITRE technique |
|---|---|---|
| **DELETED**  | HIGH    | T1070.004 (Indicator Removal — File Deletion) |
| **MODIFIED** | HIGH    | T1565.001 (Stored Data Manipulation) |
| **NEW_FILE** | MEDIUM  | T1105 (Ingress Tool Transfer) |
| **RENAMED**  | LOW     | T1036 (Masquerading) |
| **Self-tampering** | HIGH | T1562.001 (Impair Defenses) |

Severities are fixed in code and apply to every event of the given type.
        """)


def show_user_management():
    if st.session_state.role != "admin":
        st.error("Access denied. Admin only.")
        return
    
    st.title("👥 User Management")
    
    users = get_all_users()
    
    st.subheader("Existing Users")
    if users:
        users_df = pd.DataFrame(users, columns=['ID', 'Username', 'Role', 'Created', 'Last Login'])
        # Map internal role strings to display labels.  Anything we
        # don't recognise passes through unchanged so future roles
        # appear in the tble without code changes.
        _role_display = {"admin": "Admin", "local_user": "Local User"}
        users_df['Role'] = users_df['Role'].map(
            lambda r: _role_display.get(r, r))
        st.dataframe(users_df, use_container_width=True, hide_index=True)
    
    st.divider()
    
    st.subheader("Create New User")
    with st.form("create_user_form"):
        new_username = st.text_input("Username")
        new_password = st.text_input(
            "Password (min 10 chars, must contain a letter and a digit)",
            type="password")
        # Display labels are user-friendly; the underlying role string
        # stored in the database is the snake_case identifier so it's
        # safe to use in code paths and pattern checks.
        ROLE_LABELS = {"admin": "Admin", "local_user": "Local User"}
        role_choice = st.selectbox(
            "Role", list(ROLE_LABELS.keys()),
            format_func=lambda r: ROLE_LABELS[r])
        new_role = role_choice
        if st.form_submit_button("Create User"):
            if new_username and new_password:
                success, msg = create_user(new_username, new_password, new_role)
                if success:
                    st.success(msg)
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error(msg)
    
    st.divider()
    
    st.subheader("Delete User")
    if users:
        usernames = [u[1] for u in users if u[1] != st.session_state.username]
        if usernames:
            user_to_delete = st.selectbox("Select user to delete", usernames)
            if st.button("Delete User", type="primary"):
                success, msg = delete_user(user_to_delete)
                if success:
                    st.success(msg)
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error(msg)


def show_audit_log():
    st.title("📜 Log Report")
    st.caption("All security-relevant actions logged for accountability")
    
    conn = _connect()
    try:
        # Table nme in the database stays `audit_log` — the user-facing
        # rename is display-only so we don't break every query in the system.
        df = pd.read_sql_query("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200", conn)
    except Exception:
        df = pd.DataFrame()
    conn.close()
    
    if df.empty:
        st.info("No log entries yet.")
        return
    
    st.dataframe(df, use_container_width=True, hide_index=True)
    
    csv = df.to_csv(index=False).encode('utf-8')
    st.download_button("Export Log Report (CSV)", csv, "log_report.csv", "text/csv")

def show_chain_verify():
    
    import secure_chain as sc

    st.title("🔗 Tamper-Evident Audit Chain")
    st.caption("Cryptographic verification of alert log integrity")

    # ── Configuration banner ─────────────────────────────────────────────────
    if sc.is_configured():
        st.success(
            "🔐 HMAC key configured — chain entries are signed with a "
            "secret key. Tampering with the table or rebuilding it from "
            "scratch will fail verification."
        )
    else:
        st.warning(
            "⚠️ FIM_HMAC_KEY is **not set** in `.env`. New chain entries "
            "are being written without HMAC tags — the chain still "
            "detects per-entry modification (hash chain) but not "
            "wholesale replacement. Generate a key with "
            "`python secure_chain.py --key` and add it to `.env`."
        )

    if st.button("Verify Chain Integrity", type="primary"):
        with st.spinner("Verifying chain (hash chain + HMAC)..."):
            valid, message = sc.verify_chain()
            if valid:
                st.success(f"✅ {message}")
            else:
                st.error(f"❌ TAMPERING DETECTED: {message}")

    st.divider()
    st.subheader("Chain Entries (most recent 50)")

    conn = _connect()
    try:
        df = pd.read_sql_query(
            "SELECT id, timestamp, alert_data, prev_hash, entry_hash, "
            "       entry_mac "
            "FROM chained_alerts ORDER BY id DESC LIMIT 50",
            conn,
        )
    except Exception:
        df = pd.DataFrame()
    conn.close()

    if df.empty:
        st.info("No chain entries yet. Generate alerts to populate the chain.")
        return

    # Truncate hashes for readability and add a quick "Signed?" indicator.
    df["prev_hash"]  = df["prev_hash"].apply(
        lambda x: (x[:16] + "...") if isinstance(x, str) and len(x) > 16 else x)
    df["entry_hash"] = df["entry_hash"].apply(
        lambda x: (x[:16] + "...") if isinstance(x, str) and len(x) > 16 else x)
    df["Signed?"]    = df["entry_mac"].apply(
        lambda x: "🔐 HMAC" if x else "— legacy")
    # Drop the raw mac column from display; the column is dense and not
    # useful to the operator beyond the boolean.
    df = df.drop(columns=["entry_mac"])

    st.dataframe(df, use_container_width=True, hide_index=True)

    st.divider()
    with st.expander("How the audit chain protects itself"):
        st.markdown("""
**Two independent layers of tamper evidence:**

1. **Hash chain.** Each entry's hash is `SHA-256(prev_hash | timestamp | alert_data)`.
   Any change to a past entry — even one byte — breaks every entry after it.
   `verify_chain()` walks the chain and recomputes every hash.
2. **HMAC tag.** Each entry also carries `HMAC-SHA256(key, entry_hash | timestamp | alert_data)`,
   computed with a secret key in `.env` (`FIM_HMAC_KEY`).
   Without the key, an attacker who **deletes the entire `chained_alerts` table
   and rebuilds it from scratch** cannot produce valid MACs — verification fails.

**What it catches:**
- Direct edits to `alert_data` → both hash and MAC fail
- Reordering or partial deletion → `prev_hash` mismatch
- Wholesale rebuild without the key → MAC fail
- Insertion of forged rows → MAC fail

**Honest limit:** an attacker with administrator rights can read `.env` and
forge MACs. Removing this limit requires off-host signing (TPM, HSM, or a
remote signing service); documented as future work.
""")




def show_reports():
    st.title("📄 Generate Security Report")
    st.caption("Export a formatted PDF containing recent alerts and the full log report")

    st.divider()

    col1, col2 = st.columns([2, 1])
    with col1:
        st.subheader("Report Contents")
        st.markdown("""
        The generated PDF includes:
        - **Cover page** with system-wide KPI summary (files monitored, alert counts by severity)
        - **Executive summary** with event-type breakdown and MITRE ATT&CK technique coverage
        - **Recent Alerts** table — last 50 alerts, colour-coded by severity (HIGH / MEDIUM / LOW)
        - **Log Report** — last 50 entries showing all authentication and admin actions
        """)

    with col2:
        st.subheader("Options")
        alert_limit = st.number_input("Max alerts to include", min_value=10,
                                      max_value=500, value=50, step=10)
        audit_limit = st.number_input("Max log entries to include", min_value=10,
                                      max_value=500, value=50, step=10)

    st.divider()

    if st.button("🖨️ Generate PDF Report", type="primary", use_container_width=False):
        with st.spinner("Building report…"):
            try:
                from report import generate_report_bytes
                pdf_bytes = generate_report_bytes()
                timestamp = __import__('datetime').datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"FIM_Report_{timestamp}.pdf"
                log_audit(st.session_state.username, "REPORT_GENERATED",
                          f"PDF report generated: {filename}", success=1)
                st.success(f"✅ Report ready — click below to download.")
                st.download_button(
                    label="⬇️ Download PDF Report",
                    data=pdf_bytes,
                    file_name=filename,
                    mime="application/pdf",
                    use_container_width=True,
                )
            except Exception as e:
                st.error(f"Report generation failed: {e}")
                st.exception(e)

    st.divider()
    st.caption(
        "Report generation is logged in the Log Report. "
        "Each report is a point-in-time snapshot; re-generate to get the latest data."
    )


def show_self_integrity():
    st.title("🛡️ Self-Integrity Monitor")
    st.caption(
        "Verifies that the FIM's own source files have not been tampered with. "
        "Hashes are enrolled each time monitor.py starts. "
        "MITRE ATT&CK: T1562.001 — Impair Defenses: Disable or Modify Tools"
    )

    col_refresh, col_spacer = st.columns([1, 4])
    with col_refresh:
        if st.button("🔍 Run Check Now", type="primary"):
            # Force a full rerun so get_self_integrity_status() is called
            # with fresh data rather than returning a cached result.
            st.rerun()

    st.divider()

    try:
        status = get_self_integrity_status()
    except Exception as e:
        st.error(f"Could not load self-integrity status: {e}")
        st.info("Make sure monitor.py has been run at least once to enroll the baseline.")
        return

    if not status["enrolled_files"]:
        st.warning(
            "No self-baseline found. Start monitor.py to enroll the FIM source files, "
            "then return to this page."
        )
        return

    # ── Overall status banner ──────────────────────────────────────────────
    if status["all_ok"]:
        st.success(
            f"✅ All {len(status['enrolled_files'])} monitored FIM files are intact. "
            f"Last checked: {status['check_time']}"
        )
    else:
        st.error(
            f"❌ {len(status['violations'])} violation(s) detected! "
            f"Last checked: {status['check_time']}"
        )

    # ── Violations detail ──────────────────────────────────────────────────
    if status["violations"]:
        st.subheader("⚠️ Violations")
        for v in status["violations"]:
            with st.container(border=True):
                vcol1, vcol2 = st.columns([1, 3])
                with vcol1:
                    badge = "🔴 MODIFIED" if v["type"] == "MODIFIED" else "⛔ DELETED"
                    st.markdown(f"**{badge}**")
                    st.markdown(f"`{v['filename']}`")
                with vcol2:
                    st.text(f"Path:    {v['abs_path']}")
                    st.text(f"Stored:  {v['stored_hash']}")
                    if v["type"] == "MODIFIED":
                        st.text(f"Current: {v['current_hash']}")
                    else:
                        st.text("File no longer exists on disk")
        st.divider()

    # ── Enrolled files table ───────────────────────────────────────────────
    st.subheader(f"Enrolled Files ({len(status['enrolled_files'])})")
    st.caption("These are the FIM source files protected by self-monitoring. "
               "The baseline hash is re-enrolled every time monitor.py starts.")

    violated_names = {v["filename"] for v in status["violations"]}

    rows = []
    for f in status["enrolled_files"]:
        ok = f["filename"] not in violated_names
        rows.append({
            "Status":       "✅ OK" if ok else "❌ VIOLATION",
            "File":         f["filename"],
            "SHA-256 (enrolled)": f["hash"],
            "Size (bytes)": f["size"],
            "Enrolled At":  f["enrolled_at"],
        })

    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.divider()
    st.info(
        "**How it works:** When monitor.py starts, selfwatch.py hashes every FIM "
        "source file and stores the results in the `self_baseline` database table. "
        "A background thread then re-hashes the files every 30 seconds. "
        "Any change triggers a HIGH-severity alert logged to the alerts table, "
        "the tamper-evident chain, and Discord — the same pipeline as any other FIM event."
    )


# === MAIN ROUTING ===
# Check session expiry FRST so an expired session is kicked out before
# any sensitive page is rendered.  After that, refresh last_activity so
# activ use keeps the session alive — but only if the user is logged
# in and not stuck on the force-password-change screen.
if _is_session_expired():
    _force_logout("Idle for more than "
                  f"{SESSION_TIMEOUT_MINUTES} minutes")
    st.warning(
        f"Your session expired after {SESSION_TIMEOUT_MINUTES} minutes "
        "of inactivity. Please log in again."
    )

if st.session_state.logged_in:
    st.session_state.last_activity = datetime.now()

if not st.session_state.logged_in:
    show_login()
elif st.session_state.force_password_change:
    show_force_password_change()
else:
    show_dashboard()
    