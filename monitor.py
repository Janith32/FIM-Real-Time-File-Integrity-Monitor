import os
import time
import shutil
import threading
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from utils import (db_connect, hash_file, init_all_tables, get_logger,
                   can_restore, is_editor_temp)
from alerts import send_discord_alert
from auth import add_monitored_path
# Use the HMAC-protected chain instead of the plain SHA-256 one in auth.py.
# Same function signature, so log_alert() doesn't need to change.  The
# upgrade closes the "attacker wipes the table and rebuilds" gap that
# the plain hash chain leaves open — see secure_chain.py for the full
# threat-model discussion.
from secure_chain import add_to_chain
from selfwatch import start_self_watcher

# ── Configuration ─────────────────────────────────────────────────────────────

# .env lives next to monitor.py, NOT wherever you launched python from.
load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env",
            override=True)

BACKUP_PATH = os.getenv("BACKUP_PATH",
                        str(Path(__file__).resolve().parent / "Backup"))
RELOAD_INTERVAL = int(os.getenv("RELOAD_INTERVAL", "10"))

# ── Auto-restore policy ───────────────────────────────────────────────────────

_legacy_auto = os.getenv("AUTO_RESTORE")
if _legacy_auto is not None:
    _legacy = _legacy_auto.strip().lower() == "true"
    AUTO_RESTORE_ON_DELETE = _legacy
    AUTO_RESTORE_ON_MODIFY = _legacy
else:
    AUTO_RESTORE_ON_DELETE = (os.getenv("AUTO_RESTORE_ON_DELETE", "true")
                              .strip().lower() == "true")
    AUTO_RESTORE_ON_MODIFY = (os.getenv("AUTO_RESTORE_ON_MODIFY", "false")
                              .strip().lower() == "true")


MONITOR_PATH = os.getenv("MONITOR_PATH", "").strip()

log = get_logger("fim.monitor")


# ── Thread-safe shared state ──────────────────────────────────────────────────
# Watchdog dispatches events from a worker thread, so any data structure
# touched by both an event callback and the main loop needs synchronisation.

_state_lock = threading.Lock()
pending_restores = set()  # paths currently being overwritten by restore
pending_renames = set()   # paths involved in an in-flight rename


ATOMIC_SAVE_WINDOW = 0.75   # seconds
pending_deletes = {}        # path -> threading.Timer
pending_rename_to_temp = {} # path -> {timer, old_path, new_path}
_deferred_lock = threading.Lock()


def _add_pending(s, path):
    with _state_lock:
        s.add(path)


def _check_and_clear_pending(s, path):
 
    with _state_lock:
        if path in s:
            s.discard(path)
            return True
        return False


def _is_pending(s, path):
    with _state_lock:
        return path in s


def defer_delete(path, callback):
   
    timer = threading.Timer(ATOMIC_SAVE_WINDOW, callback)
    timer.daemon = True
    with _deferred_lock:
        existing = pending_deletes.get(path)
        if existing is not None:
            existing.cancel()
        pending_deletes[path] = timer
    timer.start()


def cancel_deferred_delete(path):
    
    with _deferred_lock:
        timer = pending_deletes.pop(path, None)
    if timer is not None:
        timer.cancel()
        return True
    return False


def _clear_pending_delete_record(path):
   
    with _deferred_lock:
        pending_deletes.pop(path, None)


# ── Database helpers ──────────────────────────────────────────────────────────

def get_active_paths():
    
    conn = db_connect()
    c = conn.cursor()
    try:
        c.execute("SELECT path FROM monitored_paths WHERE enabled = 1")
        paths = [row[0] for row in c.fetchall()]
    except Exception as e:
        log.warning("get_active_paths failed: %s", e)
        paths = []
    conn.close()
    return paths


# ── Severity rule cache ───────────────────────────────────────────────────────

_RULE_CACHE_TTL = 30.0           # seconds
_rule_cache = None               # list[tuple(pattern, severity)] | None
_rule_cache_loaded_at = 0.0      # monotonic timestamp
_rule_cache_lock = threading.Lock()


def invalidate_rule_cache():
    
    global _rule_cache, _rule_cache_loaded_at
    with _rule_cache_lock:
        _rule_cache = None
        _rule_cache_loaded_at = 0.0


def get_active_rules():
    
    global _rule_cache, _rule_cache_loaded_at

    with _rule_cache_lock:
        cache = _rule_cache
        age = time.monotonic() - _rule_cache_loaded_at

    if cache is not None and age < _RULE_CACHE_TTL:
        return cache

    # Cache miss or expirede — refresh.  We do the DB work OUTSIDE the
    # lock so a slow query doesn't block other event handlers.  After the
    # query, we take the lock again to publish the result.
    try:
        conn = db_connect()
        c = conn.cursor()
        c.execute("SELECT pattern, severity FROM severity_rules "
                  "WHERE enabled = 1")
        rules = c.fetchall()
        conn.close()
    except Exception as e:
        log.warning("get_active_rules failed: %s — keeping previous cache",
                    e)
        # Return whatever's currently cached (possibly stale) rather
        # than [] so a transient DB errror doesn't downgrade severity
        # classification for the duration of the outage.
        return cache if cache is not None else []

    with _rule_cache_lock:
        _rule_cache = rules
        _rule_cache_loaded_at = time.monotonic()
    return rules


def classify_severity(file_path, default_severity):
    
    rules = get_active_rules()
    file_path_lower = file_path.lower()
    for pattern, severity in rules:
        if pattern.lower() in file_path_lower:
            return severity
    return default_severity


# ── Backup ────────────────────────────────────────────────────────────────────

def create_backup_for_path(folder):
    Path(BACKUP_PATH).mkdir(parents=True, exist_ok=True)
    count = 0
    for root, dirs, files in os.walk(folder):
        for filename in files:
            src = os.path.join(root, filename)
            try:
                rel = os.path.relpath(src, folder)
                folder_name = os.path.basename(folder.rstrip("\\/"))
                dst = os.path.join(BACKUP_PATH, folder_name, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(src, dst)
                count += 1
            except Exception as e:
                log.error("Backup error for %s: %s", src, e)
    log.info("Backed up %d files from %s", count, folder)


def restore_file(path, monitor_folder):
    
    if not can_restore(path):
        log.warning("Restore rate limit reached for %s — skipping", path)
        return False

    folder_name = os.path.basename(monitor_folder.rstrip("\\/"))
    rel = os.path.relpath(path, monitor_folder)
    backup_file = os.path.join(BACKUP_PATH, folder_name, rel)

    if os.path.exists(backup_file):
        _add_pending(pending_restores, path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        shutil.copy2(backup_file, path)
        log.info("Restored from backup: %s", path)
        return True

    log.warning("No backup available for %s", path)
    return False


# ── Alert logging ─────────────────────────────────────────────────────────────

def log_alert(event_type, file_path, old_hash="", new_hash="",
              mitre="", severity="MEDIUM", action=""):
    conn = db_connect()
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "INSERT INTO alerts "
        "(timestamp, event_type, file_path, old_hash, new_hash, "
        " mitre_technique, severity, action_taken) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (timestamp, event_type, file_path, old_hash, new_hash,
         mitre, severity, action))
    conn.commit()
    conn.close()
    log.info("[%s] %s: %s", severity, event_type, file_path)

    try:
        add_to_chain(f"{event_type}|{file_path}|{severity}|{mitre}")
    except Exception as e:
        log.error("Chain log failed: %s", e)

    try:
        if send_discord_alert(event_type, file_path, severity, mitre, action):
            log.debug("Discord alert sent for %s", file_path)
        else:
            log.debug("Discord alert NOT sent (config disabled or missing)")
    except Exception as e:
        log.error("Discord alert error: %s", e)


def get_baseline(path):
    conn = db_connect()
    c = conn.cursor()
    c.execute("SELECT hash, size, mtime FROM baseline WHERE path = ?",
              (path,))
    row = c.fetchone()
    conn.close()
    return row


def add_to_baseline(path):
    
    conn = db_connect()
    c = conn.cursor()
    try:
        file_hash = hash_file(path)
        stat = os.stat(path)
        c.execute("INSERT OR REPLACE INTO baseline VALUES (?, ?, ?, ?)",
                  (path, file_hash, stat.st_size, stat.st_mtime))
        conn.commit()
    except Exception as e:
        log.error("Baseline error for %s: %s", path, e)
    conn.close()


def baseline_folder(folder):
    for root, dirs, files in os.walk(folder):
        for filename in files:
            add_to_baseline(os.path.join(root, filename))


# ── Watchdog event handler ────────────────────────────────────────────────────

class FIMHandler(FileSystemEventHandler):

    IGNORE_PATTERNS = [
        '~$', '.tmp', '~rf', '~wr', '.~tmp',
        'thumbs.db', '.ds_store', '~lock',
    ]
    DEBOUNCE_WINDOW = 2.0
    _event_counter = 0
    # Watchdog dispatches on_modified / on_created / on_deleted / on_moved
    # from a worker-thread pool, so should_process() can run concurrently
    # for different paths. 
    _debounce_lock = threading.Lock()

    def __init__(self, monitor_folder):
        self.monitor_folder = monitor_folder
        self.last_event = {}

    def should_process(self, path):
        filename = os.path.basename(path).lower()
        for pattern in self.IGNORE_PATTERNS:
            if pattern in filename:
                return False

        now = time.monotonic()

        
        with FIMHandler._debounce_lock:
            FIMHandler._event_counter += 1
            if FIMHandler._event_counter >= 200:
                cutoff = now - self.DEBOUNCE_WINDOW * 4
                stale = [p for p, t in self.last_event.items() if t < cutoff]
                for p in stale:
                    del self.last_event[p]
                FIMHandler._event_counter = 0

            if (path in self.last_event
                    and now - self.last_event[path] < self.DEBOUNCE_WINDOW):
                return False
            self.last_event[path] = now
            return True

    def check_file(self, path):
        # Suppress the modified-event echo from our own restore write.
        if _check_and_clear_pending(pending_restores, path):
            return

        if not os.path.exists(path):
            # A file was deleted from the live monitored folder.
            # We DO NOT copy it back from the backup — the backup folder
            # is the *archive* of the oiginal/baseline content, not a
            # writre-protection layer.  Deletions stick on the live side;
            # the backup copy remains as historical/forensic record.
            
            severity = classify_severity(path, "HIGH")
            log_alert("DELETED", path, mitre="T1070.004",
                      severity=severity,
                      action="Backup copy preserved in archive")
            return

        baseline = get_baseline(path)
        if baseline is None:
            severity = classify_severity(path, "MEDIUM")
            log_alert("NEW_FILE", path, mitre="T1105", severity=severity)
            add_to_baseline(path)
            try:
                folder_name = os.path.basename(
                    self.monitor_folder.rstrip("\\/"))
                rel = os.path.relpath(path, self.monitor_folder)
                backup_dest = os.path.join(BACKUP_PATH, folder_name, rel)
                os.makedirs(os.path.dirname(backup_dest), exist_ok=True)
                shutil.copy2(path, backup_dest)
                log.debug("New file backed up: %s", path)
            except Exception as e:
                log.error("Backup of new file failed: %s", e)
            return

        old_hash, old_size, old_mtime = baseline
        try:
            stat = os.stat(path)
            if stat.st_size == old_size and stat.st_mtime == old_mtime:
                return
        except Exception:
            return

        try:
            new_hash = hash_file(path)
            if new_hash != old_hash:
                
                try:
                    new_stat = os.stat(path)
                except Exception:
                    new_stat = None

                severity = classify_severity(path, "HIGH")
                action = ""
                if AUTO_RESTORE_ON_MODIFY and restore_file(path, self.monitor_folder):
                    action = "Auto-restored from backup"
                log_alert("MODIFIED", path,
                          old_hash=old_hash, new_hash=new_hash,
                          mitre="T1565.001", severity=severity, action=action)

                if new_stat is not None:
                    try:
                        conn = db_connect()
                        c = conn.cursor()
                        c.execute(
                            "INSERT OR REPLACE INTO baseline "
                            "VALUES (?, ?, ?, ?)",
                            (path, new_hash,
                             new_stat.st_size, new_stat.st_mtime),
                        )
                        conn.commit()
                        conn.close()
                    except Exception as e:
                        log.error("Failed to update baseline after "
                                  "MODIFIED: %s", e)
        except Exception as e:
            log.error("Error hashing %s: %s", path, e)

    def on_modified(self, event):
        if event.is_directory or not self.should_process(event.src_path):
            return
        time.sleep(0.5)
        self.check_file(event.src_path)

    def on_created(self, event):
        if event.is_directory or not self.should_process(event.src_path):
            return
        if _check_and_clear_pending(pending_renames, event.src_path):
            return
        self.check_file(event.src_path)

    def on_deleted(self, event):
        if event.is_directory or _is_pending(pending_restores, event.src_path):
            return
        if not self.should_process(event.src_path):
            return
        if _check_and_clear_pending(pending_renames, event.src_path):
            return

        path = event.src_path
        defer_delete(path, lambda: self._execute_deferred_delete(path))

    def _execute_deferred_delete(self, path):
        
        _clear_pending_delete_record(path)

        # If the file came back during the deferral window via some
        # path other than our atomic-save Case A (e.g., a quick
        # restore-from-backup that beat us), don't log a phantom DELETED.
        if os.path.exists(path):
            log.debug("Deferred delete cancelled — file exists: %s", path)
            return

        self.check_file(path)

    def on_moved(self, event):
        
        if event.is_directory:
            return

        old_path = event.src_path
        new_path = event.dest_path

        # ── Case A1: completion of an atomic save ────────────────────────────
        # Cancel any pending delete on the destination AND any pending
        # rename-to-temsp originating from the destinatiwon — this is
        # what stitches the Office save sequence together.
        if is_editor_temp(old_path) and not is_editor_temp(new_path):
            cancelled_delete = cancel_deferred_delete(new_path)
            cancelled_rename = self._cancel_pending_rename_to_temp(new_path)
            if cancelled_delete or cancelled_rename:
                log.debug("Atomic save collapsed: %s",
                          os.path.basename(new_path))
            time.sleep(0.2)
            log.debug("Atomic save: %s -> %s",
                      os.path.basename(old_path), os.path.basename(new_path))
            self.check_file(new_path)
            return

        # ── Case A2: start of an atomic save (real -> temp) ──────────────────
        # Defer the RENAMED logging.  If an A1 event comes back to the
        # ORIGINAL path withifn the window, this was an atomic save and
        # we cancel the defrred RENAMED.  Otherwise, the deferred
        # callback fires and logs the rename normally.
        if not is_editor_temp(old_path) and is_editor_temp(new_path):
            self._defer_rename_to_temp(old_path, new_path)
            return

        # ── Case B: genuine rename ───────────────────────────────────────────
        # Also cancel any pending delete on the destination — a
        # rename-onto-existing-file is one logical event.
        cancel_deferred_delete(new_path)
        self._log_rename(old_path, new_path)

    # ── helpers for Case A2 deferral ──────────────────────────────────────────

    def _defer_rename_to_temp(self, old_path, new_path):
        
        with _deferred_lock:
            existing = pending_rename_to_temp.get(old_path)
            if existing is not None:
                existing["timer"].cancel()
            timer = threading.Timer(
                ATOMIC_SAVE_WINDOW,
                lambda: self._execute_deferred_rename(old_path, new_path)
            )
            timer.daemon = True
            pending_rename_to_temp[old_path] = {
                "timer":    timer,
                "old_path": old_path,
                "new_path": new_path,
            }
        timer.start()

    def _cancel_pending_rename_to_temp(self, real_path):
       
        with _deferred_lock:
            entry = pending_rename_to_temp.pop(real_path, None)
        if entry is not None:
            entry["timer"].cancel()
            return True
        return False

    def _execute_deferred_rename(self, old_path, new_path):
        
        with _deferred_lock:
            pending_rename_to_temp.pop(old_path, None)
       
        if os.path.exists(old_path):
            log.debug("Deferred rename suppressed — original path "
                      "now has new content: %s", old_path)
            return
        self._log_rename(old_path, new_path)

    def _log_rename(self, old_path, new_path):
        
        _add_pending(pending_renames, old_path)
        time.sleep(0.3)

        severity = classify_severity(new_path, "LOW")
        log_alert("RENAMED", f"{old_path} -> {new_path}",
                  mitre="T1036", severity=severity)

        try:
            conn = db_connect()
            c = conn.cursor()
            c.execute("SELECT hash, size, mtime FROM baseline WHERE path = ?",
                      (old_path,))
            old_row = c.fetchone()
            if old_row:
                c.execute("DELETE FROM baseline WHERE path = ?", (old_path,))
                c.execute("INSERT OR REPLACE INTO baseline "
                          "VALUES (?, ?, ?, ?)",
                          (new_path, old_row[0], old_row[1], old_row[2]))
                conn.commit()
            conn.close()
        except Exception as e:
            log.error("Baseline update failed for rename: %s", e)

        
        def cleanup():
            time.sleep(2)
            _check_and_clear_pending(pending_renames, old_path)

        threading.Thread(target=cleanup, daemon=True).start()


# ── Dynamic observer manager ──────────────────────────────────────────────────

class DynamicMonitor:
    def __init__(self):
        self.observers = {}

    def start_path(self, path):
        if path in self.observers:
            return
        if not os.path.exists(path):
            log.warning("Path does not exist: %s", path)
            return

        log.info("Starting monitor for: %s", path)
        baseline_folder(path)
        create_backup_for_path(path)

        observer = Observer()
        handler = FIMHandler(path)
        observer.schedule(handler, path, recursive=True)
        observer.start()
        self.observers[path] = observer

    def stop_path(self, path):
        if path in self.observers:
            log.info("Stopping monitor for: %s", path)
            self.observers[path].stop()
            self.observers[path].join()
            del self.observers[path]

    def reconcile(self):
        # Pick up any newly added or removed monitored paths from the DB.
        desired = set(get_active_paths())
        active = set(self.observers.keys())
        for path in desired - active:
            self.start_path(path)
        for path in active - desired:
            self.stop_path(path)

   
        invalidate_rule_cache()

    def stop_all(self):
        for path in list(self.observers.keys()):
            self.stop_path(path)


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    
    init_all_tables()

   
    if MONITOR_PATH and not get_active_paths():
        if os.path.isdir(MONITOR_PATH):
            ok, msg = add_monitored_path(MONITOR_PATH, "system")
            if ok:
                log.info("Bootstrap: seeded MONITOR_PATH from .env -> %s",
                         MONITOR_PATH)
            else:
                log.warning("Bootstrap: could not seed MONITOR_PATH (%s)", msg)
        else:
            log.warning("Bootstrap: MONITOR_PATH from .env does not exist: %s",
                        MONITOR_PATH)

    log.info("[SELF] Enrolling self-integrity baseline...")
    start_self_watcher()

    log.info("=" * 60)
    log.info("FIM System Starting")
    log.info("=" * 60)
    log.info("Backup folder    : %s (archive only)", BACKUP_PATH)
    log.info("Restore on DELETE: false (backup preserved as archive)")
    log.info("Restore on MODIFY: %s", AUTO_RESTORE_ON_MODIFY)
    log.info("Reload interval  : %ss", RELOAD_INTERVAL)
    log.info("Self-integrity   : ENABLED")
    log.info("Configure paths via the dashboard.")
    log.info("=" * 60)

    monitor = DynamicMonitor()

    try:
        while True:
            monitor.reconcile()
            if not monitor.observers:
                log.info("No paths configured. Add paths via the dashboard.")
            time.sleep(RELOAD_INTERVAL)
    except KeyboardInterrupt:
        log.info("Stopping all monitors...")
        monitor.stop_all()
        log.info("Done.")
