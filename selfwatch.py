import os
import time
import threading
from datetime import datetime

from utils import db_connect, hash_file, get_logger

log = get_logger("fim.selfwatch")

# How often (seconds) the background thread re-checks each file.
SELF_CHECK_INTERVAL = 30

# FIM source files to protect.  selfwatch monitors itself too.
SELF_FILES = [
    "monitor.py",
    "auth.py",
    "alerts.py",
    "dashboard.py",
    "baseline.py",
    "report.py",
    "selfwatch.py",
    "utils.py",   # added — tamper-proof the shared module too
]


# ── Internal helpers ──────────────────────────────────────────────────────────

def _resolve_self_files():
   
    base_dir = os.path.dirname(os.path.abspath(__file__))
    resolved = {}
    for name in SELF_FILES:
        abs_path = os.path.join(base_dir, name)
        if os.path.exists(abs_path):
            resolved[name] = abs_path
        else:
            log.warning("[SELF] %s not found at %s — skipping enrollment",
                        name, abs_path)
    return resolved


def _init_table():
    conn = db_connect()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS self_baseline (
            filename    TEXT PRIMARY KEY,
            abs_path    TEXT NOT NULL,
            hash        TEXT NOT NULL,
            size        INTEGER NOT NULL,
            enrolled_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def _write_alert(event_type, file_path, old_hash="", new_hash=""):
    
    from alerts import send_discord_alert
    from secure_chain import add_to_chain

    mitre = "T1562.001" if event_type == "SELF_MODIFIED" else "T1070.004"
    severity = "HIGH"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = db_connect()
    c = conn.cursor()
    c.execute(
        "INSERT INTO alerts "
        "(timestamp, event_type, file_path, old_hash, new_hash, "
        " mitre_technique, severity, action_taken) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (timestamp, event_type, file_path, old_hash, new_hash,
         mitre, severity, ""))
    conn.commit()
    conn.close()

    log.warning("[!!!] [%s] %s: %s", severity, event_type, file_path)

    try:
        add_to_chain(f"{event_type}|{file_path}|{severity}|{mitre}")
    except Exception as e:
        log.error("Chain log failed: %s", e)

    try:
        if send_discord_alert(event_type, file_path, severity, mitre):
            log.debug("Discord alert sent for self-violation")
        else:
            log.debug("Discord alert NOT sent (config)")
    except Exception as e:
        log.error("Discord alert error: %s", e)


# ── Public API ────────────────────────────────────────────────────────────────

def enroll_self_baseline(verbose=True):
    
    _init_table()
    files = _resolve_self_files()
    enrolled = {}
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = db_connect()
    c = conn.cursor()
    for name, abs_path in files.items():
        try:
            file_hash = hash_file(abs_path)
            size = os.path.getsize(abs_path)
            c.execute(
                "INSERT OR REPLACE INTO self_baseline "
                "(filename, abs_path, hash, size, enrolled_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (name, abs_path, file_hash, size, timestamp))
            enrolled[name] = file_hash
            if verbose:
                log.info("[SELF] Enrolled: %s  hash=%s...",
                         name, file_hash[:16])
        except Exception as e:
            log.error("[SELF] Enrollment failed for %s: %s", name, e)
    conn.commit()
    conn.close()

    if verbose:
        log.info("[SELF] %d/%d files enrolled in self-baseline",
                 len(enrolled), len(SELF_FILES))
    return enrolled


def check_self_integrity():
    
    conn = db_connect()
    c = conn.cursor()
    c.execute("SELECT filename, abs_path, hash FROM self_baseline")
    rows = c.fetchall()
    conn.close()

    violations = []
    for filename, abs_path, stored_hash in rows:
        if not os.path.exists(abs_path):
            violations.append({
                "type":         "DELETED",
                "filename":     filename,
                "abs_path":     abs_path,
                "stored_hash":  stored_hash,
                "current_hash": None,
            })
            continue
        try:
            current_hash = hash_file(abs_path)
            if current_hash != stored_hash:
                violations.append({
                    "type":         "MODIFIED",
                    "filename":     filename,
                    "abs_path":     abs_path,
                    "stored_hash":  stored_hash,
                    "current_hash": current_hash,
                })
        except Exception as e:
            log.error("[SELF] Error hashing %s: %s", filename, e)

    return len(violations) == 0, violations


def get_self_integrity_status():
    
    conn = db_connect()
    c = conn.cursor()
    c.execute("SELECT filename, abs_path, hash, size, enrolled_at "
              "FROM self_baseline ORDER BY filename")
    enrolled_files = [
        {"filename": r[0], "abs_path": r[1], "hash": r[2],
         "size": r[3], "enrolled_at": r[4]}
        for r in c.fetchall()
    ]
    conn.close()

    all_ok, violations = check_self_integrity()
    return {
        "enrolled_files": enrolled_files,
        "all_ok":         all_ok,
        "violations":     violations,
        "check_time":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def _self_watch_loop(interval):
  
    log.info("[SELF] Self-integrity monitor active (polling every %ds)",
             interval)
    while True:
        time.sleep(interval)
        try:
            all_ok, violations = check_self_integrity()
        except Exception as e:
            log.error("[SELF] Check error: %s", e)
            continue

        if all_ok:
            continue

        for v in violations:
            if v["type"] == "MODIFIED":
                log.critical(
                    "[!!!] SELF-INTEGRITY VIOLATION — %s was MODIFIED!",
                    v['filename'])
                _write_alert("SELF_MODIFIED", v["abs_path"],
                             old_hash=v["stored_hash"],
                             new_hash=v["current_hash"])
            elif v["type"] == "DELETED":
                log.critical(
                    "[!!!] SELF-INTEGRITY VIOLATION — %s was DELETED!",
                    v['filename'])
                _write_alert("SELF_DELETED", v["abs_path"],
                             old_hash=v["stored_hash"])


def start_self_watcher(interval=SELF_CHECK_INTERVAL):
   
    enroll_self_baseline(verbose=True)
    t = threading.Thread(
        target=_self_watch_loop, args=(interval,),
        daemon=True, name="SelfWatcher")
    t.start()
    return t


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info("Running self-integrity check manually...")
    enroll_self_baseline(verbose=True)
    all_ok, violations = check_self_integrity()
    if all_ok:
        log.info("All FIM files intact.")
    else:
        log.warning("%d violation(s) detected:", len(violations))
        for v in violations:
            log.warning("  [%s] %s", v['type'], v['filename'])
            if v["type"] == "MODIFIED":
                log.warning("    stored:  %s", v['stored_hash'])
                log.warning("    current: %s", v['current_hash'])
