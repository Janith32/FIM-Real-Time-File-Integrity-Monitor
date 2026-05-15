import hmac
import hashlib
import os
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

from utils import db_connect

# Load .env from next to this file, not the CWD, so behaviour is
# consistent whether secure_chain is imported by monitor.py, the
# dashboard, or run as a CLI tool.
_ENV_PATH = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=_ENV_PATH, override=True)

DB_PATH = "fim.db"


# ── Key management ────────────────────────────────────────────────────────────

def _get_chain_key() -> bytes:
    
    key_hex = os.getenv("FIM_HMAC_KEY", "").strip()
    if not key_hex:
        raise RuntimeError(
            "FIM_HMAC_KEY is not set in .env. Generate one with:\n"
            "  python secure_chain.py --key\n"
            "Then add to .env:\n"
            "  FIM_HMAC_KEY=<your 64-character hex string>"
        )
    try:
        return bytes.fromhex(key_hex)
    except ValueError:
        raise RuntimeError("FIM_HMAC_KEY in .env is not valid hex.")


def is_configured() -> bool:
    """Quick check: is the HMAC key configured?  Used by the dashboard
    to decide whether to show 'MAC verification: enabled'."""
    try:
        _get_chain_key()
        return True
    except RuntimeError:
        return False


# ── Database helpers ──────────────────────────────────────────────────────────


# ── HMAC computation ──────────────────────────────────────────────────────────

def _compute_entry_mac(entry_hash: str, timestamp: str,
                       alert_data: str) -> str:
    
    key = _get_chain_key()
    msg = f"{entry_hash}|{timestamp}|{alert_data}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


# ── Public API: drop-in replacements for auth.add_to_chain / verify_chain ─────

def add_to_chain(alert_data: str) -> str:
    
    conn = db_connect()
    c = conn.cursor()

    # Step 1: previous entry hash
    c.execute("SELECT entry_hash FROM chained_alerts "
              "ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    prev_hash = row[0] if row else "GENESIS"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Step 2: chain link (same formula as auth.add_to_chain — by design)
    entry_content = f"{prev_hash}|{timestamp}|{alert_data}"
    entry_hash = hashlib.sha256(entry_content.encode("utf-8")).hexdigest()

    # Step 3: HMAC tag (graceful degrade if key missing)
    try:
        entry_mac = _compute_entry_mac(entry_hash, timestamp, alert_data)
    except RuntimeError as e:
        print(f"  [CHAIN] Warning: {e}")
        entry_mac = None

    # Step 4: persist
    c.execute(
        "INSERT INTO chained_alerts "
        "(timestamp, alert_data, prev_hash, entry_hash, entry_mac) "
        "VALUES (?, ?, ?, ?, ?)",
        (timestamp, alert_data, prev_hash, entry_hash, entry_mac),
    )
    conn.commit()
    conn.close()
    return entry_hash


def verify_chain():
    
    conn = db_connect()
    c = conn.cursor()
    c.execute(
        "SELECT id, timestamp, alert_data, prev_hash, entry_hash, entry_mac "
        "FROM chained_alerts ORDER BY id"
    )
    entries = c.fetchall()
    conn.close()

    if not entries:
        return True, "Chain is empty — nothing to verify."

    expected_prev = "GENESIS"
    hash_failures = []
    mac_failures = []
    unsigned_rows = 0

    key_available = is_configured()

    for (entry_id, ts, data, prev_hash, stored_hash, stored_mac) in entries:

        # ── Pass 1: hash chain ────────────────────────────────────────────
        if prev_hash != expected_prev:
            hash_failures.append(
                f"Entry {entry_id}: prev_hash mismatch "
                f"(expected {expected_prev[:12]}…, got {prev_hash[:12]}…)"
            )

        recomputed_hash = hashlib.sha256(
            f"{prev_hash}|{ts}|{data}".encode("utf-8")
        ).hexdigest()
        if recomputed_hash != stored_hash:
            hash_failures.append(
                f"Entry {entry_id}: entry_hash mismatch "
                "— content was modified"
            )

        # advance cursor regardless of fxailure so the rest of the
        # report still makes sense if multiple rows are bad
        expected_prev = stored_hash

        # ── Pass 2: HMAC ──────────────────────────────────────────────────
        if not stored_mac:
            unsigned_rows += 1
            continue

        if not key_available:
            # We have a stobred MAC but no key to verify it.  This is
            # a configuration error, not tampering — report it once.
            return False, ("Cannot verify MACs: FIM_HMAC_KEY is not set "
                           "in .env, but the chain has signed entries.")

        expected_mac = _compute_entry_mac(stored_hash, ts, data)
        if not hmac.compare_digest(expected_mac, stored_mac):
            mac_failures.append(
                f"Entry {entry_id}: MAC invalid — "
                "tampered or written with a different key"
            )

    if hash_failures or mac_failures:
        all_failures = hash_failures + mac_failures
        summary = (
            f"CHAIN TAMPERED — {len(all_failures)} failure(s) detected:\n"
            + "\n".join(f"  • {f}" for f in all_failures)
        )
        if unsigned_rows:
            summary += (f"\n  ({unsigned_rows} unsigned legacy row(s) "
                        f"skipped — run --backfill)")
        return False, summary

    if unsigned_rows == len(entries):
        return True, (
            f"Chain verified for hash integrity. {len(entries)} entries — "
            "but NONE are HMAC-signed. Run "
            "'python secure_chain.py --backfill' to add MACs."
        )

    if unsigned_rows:
        return True, (
            f"Chain verified. {len(entries)} entries — hash chain valid; "
            f"{len(entries) - unsigned_rows} MAC-signed, "
            f"{unsigned_rows} unsigned legacy."
        )

    return True, (f"Chain verified. {len(entries)} entries — "
                  "hash chain and all MACs valid.")


# ── Backfill utility ──────────────────────────────────────────────────────────

def backfill_macs() -> int:
   
    conn = db_connect()
    c = conn.cursor()
    c.execute(
        "SELECT id, entry_hash, timestamp, alert_data "
        "FROM chained_alerts WHERE entry_mac IS NULL"
    )
    rows = c.fetchall()

    count = 0
    for (entry_id, entry_hash, ts, data) in rows:
        try:
            mac = _compute_entry_mac(entry_hash, ts, data)
        except RuntimeError as e:
            conn.close()
            raise RuntimeError(f"Backfill aborted: {e}")
        c.execute("UPDATE chained_alerts SET entry_mac = ? WHERE id = ?",
                  (mac, entry_id))
        count += 1
    conn.commit()
    conn.close()
    return count


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if "--key" in sys.argv:
        # Convenience: print a fresh random 256-bit key.
        import secrets
        print(secrets.token_hex(32))
        sys.exit(0)

    if "--backfill" in sys.argv:
        try:
            n = backfill_macs()
            print(f"[CHAIN] Backfilled MACs for {n} existing entries.")
        except RuntimeError as e:
            print(f"[CHAIN] {e}")
            sys.exit(1)
        sys.exit(0)

    # Default: verify and print report
    print("\nVerifying tamper-evident audit chain...\n")
    ok, msg = verify_chain()
    print(f"  Result : {'PASS' if ok else 'FAIL'}")
    print(f"  Detail : {msg}")
    sys.exit(0 if ok else 2)
