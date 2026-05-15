import json
import os
import sqlite3
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

from utils import db_connect, get_logger

log = get_logger("fim.alerts")

_ENV_PATH = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=_ENV_PATH, override=True)


# ── Discord webhook rate limiter ──────────────────────────────────────────────

WEBHOOK_MAX_PER_WINDOW    = 4   # below Discord's 5/5s ceiling for safety
WEBHOOK_WINDOW_SECONDS    = 5
WEBHOOK_SUMMARY_INTERVAL  = 60  # at most one summary per minute

_webhook_lock = threading.Lock()
_webhook_calls: deque = deque()        # timestamps of recent successful posts
_suppressed_count = 0                  # alerts dropped since last summary
_last_summary_at = 0.0                 # monotonic time of last summary post


def _rate_limit_check():
    
    global _suppressed_count
    now = time.monotonic()
    with _webhook_lock:
        # Evict timestamps older than the window
        while _webhook_calls and now - _webhook_calls[0] > WEBHOOK_WINDOW_SECONDS:
            _webhook_calls.popleft()
        if len(_webhook_calls) >= WEBHOOK_MAX_PER_WINDOW:
            _suppressed_count += 1
            return False
        _webhook_calls.append(now)
        return True


def _maybe_emit_summary(webhook_url):
    
    global _suppressed_count, _last_summary_at
    now = time.monotonic()
    with _webhook_lock:
        if _suppressed_count == 0:
            return
        if now - _last_summary_at < WEBHOOK_SUMMARY_INTERVAL:
            return
        n = _suppressed_count
        _suppressed_count = 0
        _last_summary_at = now
    try:
        requests.post(
            webhook_url,
            json={"content":
                  f"⚠️ FIM rate limit: {n} alert(s) suppressed in the "
                  f"last {WEBHOOK_SUMMARY_INTERVAL}s. "
                  "Check the dashboard for the full list."},
            timeout=5,
        )
    except requests.exceptions.RequestException as e:
        log.debug("[DISCORD] Summary post failed: %s", e)


def _get_config():
    url = os.getenv("DISCORD_WEBHOOK_URL", "").strip()
    enabled = os.getenv("DISCORD_ENABLED", "true").strip().lower() == "true"
    return url, enabled


# ── Offline queue ─────────────────────────────────────────────────────────────


PENDING_QUEUE_MAX  = 500    # cap entries; oldest evicted first
FLUSH_INTERVAL_SEC = 30     # background flusher cadence
MAX_FLUSH_PER_CYCLE = 5     # don't blast all 500 at once when we recover

_flusher_started = False
_flusher_lock = threading.Lock()


def _is_transient_failure(exc_or_status):
    
    if isinstance(exc_or_status, (requests.exceptions.ConnectionError,
                                   requests.exceptions.Timeout)):
        return True
    if isinstance(exc_or_status, int):
        return exc_or_status >= 500 or exc_or_status == 429
    return False


def _enqueue_alert(payload, error_msg):
    """Persist a failed alert payload for later replay."""
    try:
        conn = db_connect()
        c = conn.cursor()
        # Enforce queue cap: if at limit, drop the oldst entry before
        # inserting.  This prevents disk usage running away during long
        # outages whle still keeping the most recent (most relevant)
        # alerts queued.
        c.execute("SELECT COUNT(*) FROM pending_discord_alerts")
        if c.fetchone()[0] >= PENDING_QUEUE_MAX:
            c.execute(
                "DELETE FROM pending_discord_alerts WHERE id = "
                "(SELECT id FROM pending_discord_alerts ORDER BY id LIMIT 1)"
            )
            log.warning("[DISCORD] Queue at capacity (%d); dropped oldest "
                        "entry to make room.", PENDING_QUEUE_MAX)

        c.execute(
            "INSERT INTO pending_discord_alerts "
            "(queued_at, payload_json, retry_count, last_error) "
            "VALUES (?, ?, 0, ?)",
            (datetime.now(timezone.utc).isoformat(),
             json.dumps(payload),
             str(error_msg)[:200]),
        )
        conn.commit()
        conn.close()
        log.info("[DISCORD] Alert queued for offline replay (error: %s)",
                 str(error_msg)[:80])
    except Exception as e:
        # If even queueijng fails, the alert is lost — but the SQLite
        # alerts table still has it for dashboard display, so the event
        # itself isn't gone, just the Discord notification.
        log.error("[DISCORD] Could not queue alert: %s", e)


def _flush_pending(webhook_url, max_to_send=MAX_FLUSH_PER_CYCLE):
   
    if not webhook_url:
        return 0

    try:
        conn = db_connect()
        c = conn.cursor()
        c.execute(
            "SELECT id, payload_json FROM pending_discord_alerts "
            "ORDER BY id LIMIT ?",
            (max_to_send,),
        )
        rows = c.fetchall()
        conn.close()
    except Exception as e:
        log.error("[DISCORD] Queue read failed: %s", e)
        return 0

    sent = 0
    for entry_id, payload_json in rows:
        try:
            payload = json.loads(payload_json)
            response = requests.post(webhook_url, json=payload, timeout=5)
            if response.status_code == 204:
                # Success — delete from queue
                try:
                    conn = db_connect()
                    conn.execute("DELETE FROM pending_discord_alerts "
                                 "WHERE id = ?", (entry_id,))
                    conn.commit()
                    conn.close()
                except Exception as e:
                    log.error("[DISCORD] Could not delete queued entry: %s", e)
                sent += 1
                # Rpespect rate limit during flush — without this, replaying
                # a 50-entry queue at once would trigger Discord's 429.
                time.sleep(1.2)
            elif not _is_transient_failure(response.status_code):
                # Permanent failure — delete so the queue doesn't get stuck
                log.warning("[DISCORD] Dropping queued alert id=%d due to "
                            "permanent HTTP %d", entry_id, response.status_code)
                try:
                    conn = db_connect()
                    conn.execute("DELETE FROM pending_discord_alerts "
                                 "WHERE id = ?", (entry_id,))
                    conn.commit()
                    conn.close()
                except Exception:
                    pass
            else:
                # Transient failure — increment retry count, stop the cycle
                try:
                    conn = db_connect()
                    conn.execute(
                        "UPDATE pending_discord_alerts "
                        "SET retry_count = retry_count + 1, last_error = ? "
                        "WHERE id = ?",
                        (f"HTTP {response.status_code}", entry_id))
                    conn.commit()
                    conn.close()
                except Exception:
                    pass
                return sent  # Discord still down; stop flushing
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout) as e:
            # Still offline — bump retry count and stop
            try:
                conn = db_connect()
                conn.execute(
                    "UPDATE pending_discord_alerts "
                    "SET retry_count = retry_count + 1, last_error = ? "
                    "WHERE id = ?",
                    (str(e)[:200], entry_id))
                conn.commit()
                conn.close()
            except Exception:
                pass
            return sent
        except Exception as e:
            log.error("[DISCORD] Unexpected flush error: %s", e)
            return sent

    if sent:
        log.info("[DISCORD] Replayed %d queued alert(s).", sent)
    return sent


def _flusher_loop():
    
    while True:
        try:
            time.sleep(FLUSH_INTERVAL_SEC)
            url, enabled = _get_config()
            if not enabled or not url:
                continue
            # Cheap probe: skip the flush attempt entirely if queue is empty
            try:
                conn = db_connect()
                c = conn.cursor()
                c.execute("SELECT COUNT(*) FROM pending_discord_alerts")
                pending = c.fetchone()[0]
                conn.close()
            except Exception:
                pending = 0
            if pending > 0:
                _flush_pending(url)
        except Exception as e:
            log.error("[DISCORD] Flusher loop error: %s", e)


def _start_flusher():
    
    global _flusher_started
    with _flusher_lock:
        if _flusher_started:
            return
        t = threading.Thread(target=_flusher_loop, daemon=True,
                              name="discord-flusher")
        t.start()
        _flusher_started = True
        log.info("[DISCORD] Offline-queue flusher started "
                 "(interval=%ds, queue cap=%d)",
                 FLUSH_INTERVAL_SEC, PENDING_QUEUE_MAX)


def queue_stats():
   
    try:
        conn = db_connect()
        c = conn.cursor()
        c.execute("SELECT COUNT(*), MIN(queued_at) FROM pending_discord_alerts")
        row = c.fetchone()
        conn.close()
        return (row[0] or 0, row[1])
    except Exception:
        return (0, None)


def send_discord_alert(event_type, file_path, severity, mitre_technique,
                       action_taken=""):
    webhook_url, enabled = _get_config()

    if not enabled:
        return False
    if not webhook_url or webhook_url == "PASTE_YOUR_WEBHOOK_URL_HERE":
        return False

  
    _start_flusher()

    if not _rate_limit_check():
        log.debug("[DISCORD] Rate limited — suppressing alert for %s",
                  file_path)
        return False

    color_map = {"HIGH": 15158332, "MEDIUM": 15844367, "LOW": 3066993}
    color = color_map.get(severity, 9807270)

    embed = {
        "title":       f"🚨 FIM Alert: {event_type}",
        "description": f"**Severity:** {severity}",
        "color":       color,
        "fields": [
            {"name": "File Path",    "value": f"`{file_path}`",
             "inline": False},
            {"name": "MITRE ATT&CK", "value": mitre_technique or "N/A",
             "inline": True},
            {"name": "Severity",     "value": severity,
             "inline": True},
        ],
        "footer":    {"text": "Real-Time File Integrity Monitor"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if action_taken:
        embed["fields"].append({
            "name": "Action Taken", "value": action_taken, "inline": False})

    payload = {"username": "FIM Bot", "embeds": [embed]}

    try:
        response = requests.post(webhook_url, json=payload, timeout=5)
        if response.status_code == 204:
            # Successul send — opportunistically flush a summary if
            # alerts have been suppressed since the last one, AND
            # opportunistically flush a few queued alerts in case Discord
            # was previously offline.  T
            _maybe_emit_summary(webhook_url)
            _flush_pending(webhook_url, max_to_send=MAX_FLUSH_PER_CYCLE)
            return True

        # Discord returned a non-204 status.  Decide whether to queue.
        if _is_transient_failure(response.status_code):
            log.warning("[DISCORD] Transient HTTP %d — queueing for replay",
                        response.status_code)
            _enqueue_alert(payload, f"HTTP {response.status_code}")
        else:
            log.error("[DISCORD] FAILED — HTTP %d: %s (not queued — permanent)",
                      response.status_code, response.text[:200])
        return False
    except requests.exceptions.ConnectionError as e:
        log.warning("[DISCORD] Connection error — queueing for replay: %s",
                    str(e)[:120])
        _enqueue_alert(payload, str(e))
        return False
    except requests.exceptions.Timeout:
        log.warning("[DISCORD] Timeout after 5s — queueing for replay")
        _enqueue_alert(payload, "timeout after 5s")
        return False
    except requests.exceptions.RequestException as e:
        # Generic catch — be conservative and queue.  If the error is
        # actually permanent, the flusher will eventually drop the entry
        # (via _is_transient_failure check on retry).
        log.warning("[DISCORD] Request error — queueing for replay: %s",
                    str(e)[:120])
        _enqueue_alert(payload, str(e))
        return False


def diagnose():
    """Run `python alerts.py` to test Discord configuration."""
    print("=" * 55)
    print("Discord Configuration Diagnostics")
    print("=" * 55)
    print(f"\n.env path   : {_ENV_PATH}")
    print(f".env exists  : {_ENV_PATH.exists()}")

    webhook_url, enabled = _get_config()
    print(f"DISCORD_ENABLED     = {enabled}")

    if not webhook_url or webhook_url == "PASTE_YOUR_WEBHOOK_URL_HERE":
        print("DISCORD_WEBHOOK_URL = NOT SET")
        print("\n  Fix: paste your webhook URL into .env:")
        print("       DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...")
        return

    print(f"DISCORD_WEBHOOK_URL = {webhook_url[:55]}...  (set)")

    if not enabled:
        print("\n  Fix: set DISCORD_ENABLED=true in .env")
        return

    print("\nSending test message to Discord...")
    try:
        r = requests.post(webhook_url,
                          json={"content": "✅ FIM test — Discord alerts working!"},
                          timeout=5)
        print(f"HTTP Status: {r.status_code}")
        if r.status_code == 204:
            print("SUCCESS — check your Discord channel.")
        elif r.status_code == 404:
            print("FAIL 404 — webhook URL invalid or deleted.")
            print("  Regenerate the webhook in Discord → Server Settings → Integrations.")
        elif r.status_code == 401:
            print("FAIL 401 — invalid webhook token.")
        elif r.status_code == 429:
            print("FAIL 429 — rate limited. Wait a minute and retry.")
        else:
            print(f"FAIL — {r.text[:300]}")
    except requests.exceptions.ConnectionError:
        print("FAIL — No network connection.")
    except requests.exceptions.Timeout:
        print("FAIL — Request timed out.")


if __name__ == "__main__":
    diagnose()
