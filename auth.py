import os
import bcrypt
import hashlib
import re
from datetime import datetime, timedelta

from utils import db_connect, get_logger, init_all_tables

log = get_logger("fim.auth")

LOCKOUT_MAX_ATTEMPTS = 5
LOCKOUT_WINDOW_MINUTES = 15

PASSWORD_MIN_LENGTH = 10


def validate_password_policy(password: str):
    
    if password is None or len(password) < PASSWORD_MIN_LENGTH:
        return False, (f"Password must be at least "
                       f"{PASSWORD_MIN_LENGTH} characters")
    if not re.search(r"[A-Za-z]", password):
        return False, "Password must contain at least one letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit"
    return True, "OK"

_DUMMY_HASH = bcrypt.hashpw(b"dummy_password_for_timing_only",
                            bcrypt.gensalt(rounds=12))


# ── User table & password helpers ─────────────────────────────────────────────

def init_users_table():
   
    init_all_tables()


def hash_password(password):
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def verify_password(password, password_hash):
    return bcrypt.checkpw(password.encode('utf-8'),
                          password_hash.encode('utf-8'))


def create_user(username, password, role, force_change=False, _skip_policy=False):
   
    if role not in ['admin', 'local_user']:
        return False, "Invalid role"

    if not _skip_policy:
        ok, msg = validate_password_policy(password)
        if not ok:
            return False, msg

    conn = db_connect()
    c = conn.cursor()
    try:
        password_hash = hash_password(password)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute(
            "INSERT INTO users "
            "(username, password_hash, role, created_at, force_password_change)"
            " VALUES (?, ?, ?, ?, ?)",
            (username, password_hash, role, timestamp, int(force_change)))
        conn.commit()
        log_audit(username, "USER_CREATED", f"Role: {role}", success=1)
        return True, "User created successfully"
    except Exception as e:
        if "UNIQUE" in str(e):
            return False, "Username already exists"
        return False, f"DB error: {e}"
    finally:
        conn.close()


def clear_force_password_change(username):
    
    conn = db_connect()
    c = conn.cursor()
    c.execute("UPDATE users SET force_password_change = 0 WHERE username = ?",
              (username,))
    conn.commit()
    conn.close()


# ── Lockout & authentication ──────────────────────────────────────────────────

def is_account_locked(username):
    
    conn = db_connect()
    c = conn.cursor()
    try:
        cutoff = (datetime.now() - timedelta(minutes=LOCKOUT_WINDOW_MINUTES))\
                 .strftime("%Y-%m-%d %H:%M:%S")
        c.execute("""
            SELECT COUNT(*) FROM audit_log
            WHERE username = ?
              AND action = 'LOGIN_FAILED'
              AND success = 0
              AND timestamp >= ?
        """, (username, cutoff))
        count = c.fetchone()[0]
    except Exception as e:
        log.warning("Lockout check failed for %s: %s", username, e)
        count = 0
    finally:
        conn.close()

    return count >= LOCKOUT_MAX_ATTEMPTS


def authenticate(username, password):
    
    if is_account_locked(username):
        log_audit(username, "LOGIN_BLOCKED",
                  f"Account locked after {LOCKOUT_MAX_ATTEMPTS} failed attempts "
                  f"within {LOCKOUT_WINDOW_MINUTES} minutes", success=0)
        return False, "LOCKED"

    conn = db_connect()
    c = conn.cursor()
    c.execute(
        "SELECT password_hash, role, force_password_change "
        "FROM users WHERE username = ?", (username,))
    row = c.fetchone()

    if row is None:
        # Burn equihvalent CPU time on a dummy hash so failed logins for
        # nonexistent users take the same time as failed logins for real
        # ones.  Tis closes the bcrypt timing oracle.
        bcrypt.checkpw(password.encode('utf-8'), _DUMMY_HASH)
        log_audit(username, "LOGIN_FAILED", "User does not exist", success=0)
        conn.close()
        return False, None

    password_hash, role, force_change = row
    if verify_password(password, password_hash):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("UPDATE users SET last_login = ? WHERE username = ?",
                  (timestamp, username))
        conn.commit()
        log_audit(username, "LOGIN_SUCCESS", f"Role: {role}", success=1)
        conn.close()
        # Pass force_change back to the dashboard via a tuple so it can
        # decide to redrect to the password-change screen.
        return True, {"role": role, "force_change": bool(force_change)}
    else:
        log_audit(username, "LOGIN_FAILED", "Wrong password", success=0)
        conn.close()
        return False, None


def log_audit(username, action, details="", success=1):
    conn = db_connect()
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO audit_log "
              "(timestamp, username, action, details, success) "
              "VALUES (?, ?, ?, ?, ?)",
              (timestamp, username, action, details, success))
    conn.commit()
    conn.close()


# ── User management ───────────────────────────────────────────────────────────

def get_all_users():
    conn = db_connect()
    c = conn.cursor()
    c.execute("SELECT id, username, role, created_at, last_login "
              "FROM users ORDER BY id")
    users = c.fetchall()
    conn.close()
    return users


def delete_user(username):
    
    conn = db_connect()
    c = conn.cursor()
    try:
        c.execute("SELECT role FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        if row is None:
            return False, f"User '{username}' does not exist"

        # Block last-admin deletion at the data layer.  The dashboard's
        # selectbox already filters out the current user, so this guard
        # primarily catches "I deleted my admin colleague and I'm a
        # local user" scenarios.
        if row[0] == "admin":
            c.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
            admin_count = c.fetchone()[0]
            if admin_count <= 1:
                return False, ("Cannot delete the last admin account — "
                               "the system would be left with no way to "
                               "manage users.")

        c.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        log_audit(username, "USER_DELETED", success=1)
        return True, f"User {username} deleted"
    finally:
        conn.close()


def init_default_admin():
    
    init_users_table()
    conn = db_connect()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users")
    count = c.fetchone()[0]
    conn.close()

    if count == 0:
        success, msg = create_user("admin", "ChangeMe123", "admin",
                                   force_change=True, _skip_policy=True)
        if success:
            log.warning("Default admin created — username=admin, "
                        "password=ChangeMe123. CHANGE IMMEDIATELY ON FIRST LOGIN.")


# ── Configuration tables (paths + severity rules) ─────────────────────────────

def init_config_tables():
   
    init_all_tables()


def add_monitored_path(path, username):
   
    # ── Pre-insert validation ───────────────────────────────────────────────
    if not path or not path.strip():
        return False, "Path cannot be empty"
    path = path.strip()

    # Reject relative paths — monitor.py joins paths verbatim and a
    # relative path would resolve differently depending on where the
    # service was launched from, breaking the watch list silently.
    if not os.path.isabs(path):
        return False, "Path must be absolute (e.g. D:\\folder, not folder)"

    if not os.path.exists(path):
        return False, f"Path does not exist on disk: {path}"
    if not os.path.isdir(path):
        return False, f"Path exists but is not a folder: {path}"

    init_config_tables()
    conn = db_connect()
    c = conn.cursor()
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO monitored_paths (path, added_by, added_at) "
                  "VALUES (?, ?, ?)", (path, username, timestamp))
        conn.commit()
        log_audit(username, "PATH_ADDED", f"Path: {path}", success=1)
        return True, "Path added"
    except Exception as e:
        if "UNIQUE" in str(e):
            return False, "Path already exists"
        return False, f"DB error: {e}"
    finally:
        conn.close()


def remove_monitored_path(path, username):
    conn = db_connect()
    c = conn.cursor()
    c.execute("DELETE FROM monitored_paths WHERE path = ?", (path,))
    conn.commit()
    conn.close()
    log_audit(username, "PATH_REMOVED", f"Path: {path}", success=1)


def get_monitored_paths():
    init_config_tables()
    conn = db_connect()
    c = conn.cursor()
    c.execute("SELECT id, path, enabled, added_by, added_at "
              "FROM monitored_paths")
    paths = c.fetchall()
    conn.close()
    return paths


def add_severity_rule(rule_name, pattern, severity, username):
    
    rule_name = (rule_name or "").strip()
    pattern   = (pattern or "").strip()
    if not rule_name:
        return False, "Rule name cannot be empty"
    if not pattern:
        return False, ("Pattern cannot be empty — an empty pattern would "
                       "match every file and override all other rules")
    if severity not in ("HIGH", "MEDIUM", "LOW"):
        return False, "Severity must be HIGH, MEDIUM, or LOW"

    init_config_tables()
    conn = db_connect()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO severity_rules (rule_name, pattern, severity) "
                  "VALUES (?, ?, ?)", (rule_name, pattern, severity))
        conn.commit()
        log_audit(username, "RULE_ADDED",
                  f"{rule_name}: {pattern} -> {severity}", success=1)
        return True, "Rule added"
    except Exception as e:
        return False, f"DB error: {e}"
    finally:
        conn.close()


def remove_severity_rule(rule_id, username):
    conn = db_connect()
    c = conn.cursor()
    c.execute("DELETE FROM severity_rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()
    log_audit(username, "RULE_REMOVED", f"Rule ID: {rule_id}", success=1)


def get_severity_rules():
    init_config_tables()
    conn = db_connect()
    c = conn.cursor()
    c.execute("SELECT id, rule_name, pattern, severity, enabled "
              "FROM severity_rules")
    rules = c.fetchall()
    conn.close()
    return rules


# ── Tamper-evident hash chain ─────────────────────────────────────────────────
#
# The chained_alerts table is created by utils.init_all_tables() at startup.
# Earlier versions of this file had its own init_chained_log_table() function
# but nothing called it and it duplicated the canonical schema; removed.


def add_to_chain(alert_data):
    
    conn = db_connect()
    c = conn.cursor()

    c.execute("SELECT entry_hash FROM chained_alerts ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    prev_hash = row[0] if row else "GENESIS"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry_content = f"{prev_hash}|{timestamp}|{alert_data}"
    entry_hash = hashlib.sha256(entry_content.encode()).hexdigest()

    c.execute("INSERT INTO chained_alerts "
              "(timestamp, alert_data, prev_hash, entry_hash) "
              "VALUES (?, ?, ?, ?)",
              (timestamp, alert_data, prev_hash, entry_hash))
    conn.commit()
    conn.close()


def verify_chain():
   
    conn = db_connect()
    c = conn.cursor()
    c.execute("SELECT id, timestamp, alert_data, prev_hash, entry_hash "
              "FROM chained_alerts ORDER BY id")
    entries = c.fetchall()
    conn.close()

    if not entries:
        return True, "Chain is empty"

    expected_prev = "GENESIS"
    for entry_id, ts, data, prev_hash, entry_hash in entries:
        if prev_hash != expected_prev:
            return False, (f"Chain broken at entry {entry_id}: "
                           "prev_hash mismatch")
        recomputed = hashlib.sha256(
            f"{prev_hash}|{ts}|{data}".encode()).hexdigest()
        if recomputed != entry_hash:
            return False, (f"Chain broken at entry {entry_id}: "
                           "entry_hash mismatch (tampering detected)")
        expected_prev = entry_hash

    return True, f"Chain verified. {len(entries)} entries intact."


if __name__ == "__main__":
    init_default_admin()
