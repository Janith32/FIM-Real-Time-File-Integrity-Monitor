import hashlib
import logging
import os
import sqlite3
import threading
import time
from collections import deque
from logging.handlers import RotatingFileHandler
from typing import Optional

# ── Constants ─────────────────────────────────────────────────────────────────

DB_PATH = "fim.db"

# Files whose names or extensions indicate an editor temp / atomic-save artefact.
# Used by monitor.py's on_moved handler to distijnguish editor saves from genuine
# file renames.
EDITOR_TEMP_PATTERNS = [
    ".tmp",     # generic temp
    "~rf",      # Notepad/Word recovery
    "~wr",      # Word write temp
    "~$",       # Word/Excel lock file
    ".~tmp",    # Excel temp
    "~lock",    # LibreOffice lock
    ".crswap",  # VS Code / Chrome swap
    ".part",    # partial downloads
    ".swp",     # Vim swap
    ".bak",     # generic backup written before overwrite
]


# ── Logging ───────────────────────────────────────────────────────────────────

def setup_logging(
    name: str = "fim",
    log_file: str = "fim.log",
    level: int = logging.INFO,
) -> logging.Logger:
    
    logger = logging.getLogger(name)

    # Guard: don't add duplicate handlers if the module is reloaded
    if logger.handlers:
        return logger

    logger.setLevel(level)

    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console — INFO and above
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(fmt)
    logger.addHandler(console)

    # Rotating file — DEBUG and above (captures everything for post-mortem)
    try:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,  # 5 MB
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)
    except OSError as e:
        # If the log file cran't be created (e.g. read-only filesystem during
        # testing), fall back gracefully to console-only logging.
        logger.warning("Could not open log file %s: %s — logging to console only", log_file, e)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Shorthand: returns an existing logger or creates one with defaults."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        return setup_logging(name)
    return logger


# ── Database connection ────────────────────────────────────────────────────────

def db_connect(db_path: str = DB_PATH, retries: int = 6) -> sqlite3.Connection:
   
    log = get_logger("fim.db")
    last_error: Optional[sqlite3.OperationalError] = None

    for attempt in range(retries):
        try:
            conn = sqlite3.connect(db_path, timeout=20, check_same_thread=False)
            # Enable WAL — idempotent, safe to call on every new connection
            conn.execute("PRAGMA journal_mode=WAL")
            # NORMAL is crash-safe with WAL and much faster than FULL
            conn.execute("PRAGMA synchronous=NORMAL")
            # Ask SQLite itself to wait up to 5 s before surfacing SQLITE_BUSY
            conn.execute("PRAGMA busy_timeout=5000")
            # Keep SQLite's page cache warm across calls
            conn.execute("PRAGMA cache_size=-8000")  # 8 MB
            conn.row_factory = sqlite3.Row  # allows dict-style column access
            return conn
        except sqlite3.OperationalError as e:
            last_error = e
            wait = 0.2 * (2 ** attempt)  # 0.2, 0.4, 0.8, 1.6, 3.2, 6.4 s
            log.warning(
                "DB connection attempt %d/%d failed (%s) — retrying in %.1fs",
                attempt + 1, retries, e, wait,
            )
            time.sleep(wait)

    raise last_error  # type: ignore[misc]


# ── File hashing ───────────────────────────────────────────────────────────────

def hash_file(path: str, retries: int = 5, base_delay: float = 0.3) -> str:
    
    log = get_logger("fim.hash")
    last_error: Optional[Exception] = None

    for attempt in range(retries):
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()

        except FileNotFoundError:
            # File was deleted between the event and the hash attempt —
            # do not retry, propagatef immediately so the caller can log DELETED.
            raise

        except PermissionError as e:
            # Windows file lock — very common with editors and AV software.
            last_error = e
            wait = base_delay * (attempt + 1)
            log.debug(
                "PermissionError hashing %s (attempt %d/%d) — retrying in %.1fs",
                path, attempt + 1, retries, wait,
            )
            time.sleep(wait)

        except OSError as e:
            # winerror 32 = ERROR_SHARING_VIOLATION (file in use by another process)
            # winerror 5  = ERROR_ACCESS_DENIED
            last_error = e
            wait = base_delay * (attempt + 1)
            log.debug(
                "OSError %s hashing %s (attempt %d/%d) — retrying in %.1fs",
                e, path, attempt + 1, retries, wait,
            )
            time.sleep(wait)

    log.error("Failed to hash %s after %d attempts: %s", path, retries, last_error)
    raise last_error  # type: ignore[misc]


# ── Restore rate limiter ───────────────────────────────────────────────────────

# Module-level tracker: maps file path → deque of UNIX timestamps of recent
# restore attempts.  Using a deque makes sliding-window checks O(1).
#
# Watchdog dispatches events from a worker-thread pool, so can_restore()
# can be called concurently for different paths.  Without the lock,
# two threads could mutate the tracker dict at the same time — at best
# losing a deque entry, at worst raising
# "RuntimeError: dictionary changed size during iteration".
_restore_tracker: dict[str, deque] = {}
_restore_lock = threading.Lock()


def can_restore(path: str, max_attempts: int = 3, window_seconds: int = 60) -> bool:
    
    now = time.monotonic()

    with _restore_lock:
        if path not in _restore_tracker:
            _restore_tracker[path] = deque()

        q = _restore_tracker[path]

        # Evict timestamps that have fallen outside the rolling window
        while q and now - q[0] > window_seconds:
            q.popleft()

        if len(q) >= max_attempts:
            return False

        q.append(now)
        return True


# ── Database table initialisation ─────────────────────────────────────────────

def init_all_tables(db_path: str = DB_PATH) -> None:
 
    log = get_logger("fim.db")
    log.info("Initialising all database tables in %s", db_path)

    conn = db_connect(db_path)
    c = conn.cursor()

    # ── Schema migrations for legacy databases ───────────────────────────────
    # If an older fim.db is present (created before force_password_chae was
    # added to the canonical users schema), add the column via ALTER TABLE.
    # Idempotent: the OperationalError on the second call is swallowed.
    try:
        c.execute("PRAGMA table_info(users)")
        cols = [row[1] for row in c.fetchall()]
        if cols and "force_password_change" not in cols:
            c.execute("ALTER TABLE users ADD COLUMN "
                      "force_password_change INTEGER DEFAULT 0")
            log.info("Migrated legacy users table: "
                     "added force_password_change column")
    except sqlite3.OperationalError:
        # Table doesn't exist yet — fresh DB, the CREATE TABLE below will
        # use the new schema directly. No migration needed.
        pass

    # Same idea for the chained_alerts.entry_mac column added when the
    # HMAC chain (secure_chain.py) was introduced.  Existing rows from
    # before this upgrasae have NULL MACs and are reported as "unsigned
    # legacy" by verify_chain() until backfill.
    try:
        c.execute("PRAGMA table_info(chained_alerts)")
        cols = [row[1] for row in c.fetchall()]
        if cols and "entry_mac" not in cols:
            c.execute("ALTER TABLE chained_alerts ADD COLUMN entry_mac TEXT")
            log.info("Migrated legacy chained_alerts table: "
                     "added entry_mac column")
    except sqlite3.OperationalError:
        pass

    c.executescript("""
        -- Authentication
        CREATE TABLE IF NOT EXISTS users (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            username              TEXT    UNIQUE NOT NULL,
            password_hash         TEXT    NOT NULL,
            role                  TEXT    NOT NULL,
            created_at            TEXT    NOT NULL,
            last_login            TEXT,
            force_password_change INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT    NOT NULL,
            username  TEXT,
            action    TEXT    NOT NULL,
            details   TEXT,
            success   INTEGER
        );

        -- File monitoring
        CREATE TABLE IF NOT EXISTS baseline (
            path  TEXT PRIMARY KEY,
            hash  TEXT,
            size  INTEGER,
            mtime REAL
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT,
            event_type      TEXT,
            file_path       TEXT,
            old_hash        TEXT,
            new_hash        TEXT,
            mitre_technique TEXT,
            severity        TEXT,
            action_taken    TEXT
        );

        -- Configuration
        CREATE TABLE IF NOT EXISTS monitored_paths (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            path     TEXT    UNIQUE NOT NULL,
            enabled  INTEGER DEFAULT 1,
            added_by TEXT,
            added_at TEXT
        );

        CREATE TABLE IF NOT EXISTS severity_rules (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_name TEXT    NOT NULL,
            pattern   TEXT    NOT NULL,
            severity  TEXT    NOT NULL,
            enabled   INTEGER DEFAULT 1
        );

        -- Tamper-evident chain.
        -- entry_mac (HMAC tag) is added by secure_chain.py — added here
        -- as part of the canonical schema so fresh databases include it
        -- from the start.  Existing databases get the column via the
        -- ALTER TABLE migration above the executescript block.
        CREATE TABLE IF NOT EXISTS chained_alerts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT    NOT NULL,
            alert_data TEXT    NOT NULL,
            prev_hash  TEXT    NOT NULL,
            entry_hash TEXT    NOT NULL,
            entry_mac  TEXT
        );

        -- Self-integrity
        CREATE TABLE IF NOT EXISTS self_baseline (
            filename    TEXT PRIMARY KEY,
            abs_path    TEXT NOT NULL,
            hash        TEXT NOT NULL,
            size        INTEGER NOT NULL,
            enrolled_at TEXT NOT NULL
        );

        -- Discord offline queue.
        --
        -- When Discord can't be reached (no internet, webhook 5xx, timeout)
        -- the alert payload is queued here instead of being lost.  A
        -- background flusher in alerts.py drains the queue when Discord
        -- comes back online.  Capped at ~500 entries; oldest evicted first
        -- to prevent runaway disk use during long outages.
        --
        -- payload_json is the full JSON body that would have been POST'd
        -- to the webhook, so the flusher just resends it verbatim — no
        -- need to reconstruct embeds from individual fields.
        CREATE TABLE IF NOT EXISTS pending_discord_alerts (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            queued_at     TEXT    NOT NULL,
            payload_json  TEXT    NOT NULL,
            retry_count   INTEGER DEFAULT 0,
            last_error    TEXT
        );
    """)

    conn.commit()
    conn.close()
    log.info("All tables ready.")


# ── Misc helpers ───────────────────────────────────────────────────────────────

def is_editor_temp(path: str) -> bool:
   
    name = os.path.basename(path).lower()
    if name.startswith("~"):
        return True
    return any(pattern in name for pattern in EDITOR_TEMP_PATTERNS)
