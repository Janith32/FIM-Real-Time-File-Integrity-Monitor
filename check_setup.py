import os
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
ENV_FILE = PROJECT_DIR / ".env"

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def ok(msg):    print(f"{GREEN}[ OK ]{RESET} {msg}")
def fail(msg):  print(f"{RED}[FAIL]{RESET} {msg}")
def warn(msg):  print(f"{YELLOW}[WARN]{RESET} {msg}")

errors = 0
warnings = 0


# ── 1. .env file present ──────────────────────────────────────────────────────
print("\n=== Configuration file ===")
if not ENV_FILE.exists():
    fail(f".env not found at {ENV_FILE}")
    fail("Copy .env.example to .env and fill in the values.")
    sys.exit(1)
ok(f".env found at {ENV_FILE}")

# Common Windows trap: .env saved as .env.txt
env_txt = PROJECT_DIR / ".env.txt"
if env_txt.exists():
    warn(".env.txt also exists — Windows may have appended .txt. "
         "Rename it to just .env (enable file extensions in Explorer first).")
    warnings += 1


# ── 2. Load and validate vars ─────────────────────────────────────────────────
print("\n=== Environment variables ===")
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=ENV_FILE, override=True)
except ImportError:
    fail("python-dotenv is not installed. Run: pip install python-dotenv")
    errors += 1

webhook = os.getenv("DISCORD_WEBHOOK_URL", "").strip()
monitor_path = os.getenv("MONITOR_PATH", "").strip()
backup_path = os.getenv("BACKUP_PATH", "").strip()
hmac_key = os.getenv("FIM_HMAC_KEY", "").strip()

if not webhook or webhook == "PASTE_YOUR_WEBHOOK_URL_HERE":
    fail("DISCORD_WEBHOOK_URL is not set in .env")
    errors += 1
elif not webhook.startswith("https://discord.com/api/webhooks/"):
    fail(f"DISCORD_WEBHOOK_URL does not look like a Discord webhook URL")
    fail(f"  Got: {webhook[:60]}...")
    fail(f"  Expected: https://discord.com/api/webhooks/...")
    errors += 1
else:
    ok(f"DISCORD_WEBHOOK_URL set ({webhook[:55]}...)")

# FIM_HMAC_KEY is required for secure_chain.py to write audit-log entries.
# We accept the placeholder string in .env.example as "not set" so a
# fresh copy doesn't pass this check.
if (not hmac_key
        or hmac_key.startswith("GENERATE_WITH_")
        or hmac_key == "PASTE_YOUR_HMAC_KEY_HERE"):
    fail("FIM_HMAC_KEY is not set in .env")
    fail("  Generate one with:")
    fail("    python -c \"import secrets; print(secrets.token_hex(32))\"")
    fail("  Then add to .env: FIM_HMAC_KEY=<the 64-char hex output>")
    errors += 1
else:
    # Sanity-check the format
    try:
        decoded = bytes.fromhex(hmac_key)
        if len(decoded) < 16:
            fail(f"FIM_HMAC_KEY is too short ({len(decoded)} bytes, need ≥16)")
            errors += 1
        else:
            ok(f"FIM_HMAC_KEY set ({len(decoded)} bytes)")
    except ValueError:
        fail("FIM_HMAC_KEY is not valid hex — regenerate it")
        errors += 1

if not monitor_path:
    warn("MONITOR_PATH not set. You'll need to add paths via the dashboard.")
    warnings += 1
else:
    ok(f"MONITOR_PATH = {monitor_path}")

if not backup_path:
    warn("BACKUP_PATH not set — auto-restore will use the default folder.")
    warnings += 1
else:
    ok(f"BACKUP_PATH = {backup_path}")


# ── 3. Folders exist ──────────────────────────────────────────────────────────
print("\n=== Folders ===")
if monitor_path:
    if Path(monitor_path).is_dir():
        ok(f"MONITOR_PATH folder exists")
    else:
        fail(f"MONITOR_PATH folder does NOT exist: {monitor_path}")
        fail(f"  Create it with: mkdir \"{monitor_path}\"")
        errors += 1

if backup_path:
    if Path(backup_path).is_dir():
        ok(f"BACKUP_PATH folder exists")
    else:
        fail(f"BACKUP_PATH folder does NOT exist: {backup_path}")
        fail(f"  Create it with: mkdir \"{backup_path}\"")
        errors += 1


# ── 4. Required Python packages ───────────────────────────────────────────────
print("\n=== Dependencies ===")
required = ["bcrypt", "watchdog", "dotenv", "requests", "streamlit",
            "pandas", "altair", "reportlab"]
for pkg in required:
    try:
        __import__(pkg if pkg != "dotenv" else "dotenv")
        ok(f"{pkg} installed")
    except ImportError:
        fail(f"{pkg} NOT installed.  Run: pip install {pkg}")
        errors += 1


# ── 5. Test the Discord webhook ───────────────────────────────────────────────
print("\n=== Discord webhook test ===")
if errors == 0 and webhook and webhook.startswith("https://"):
    try:
        import requests
        r = requests.post(webhook,
                          json={"content": "✅ check_setup.py — webhook reachable"},
                          timeout=5)
        if r.status_code == 204:
            ok("Discord webhook returned 204 (success). Check your channel.")
        elif r.status_code == 404:
            fail("Discord returned 404 — webhook URL is invalid or deleted.")
            fail("  Regenerate it in Discord: Channel Settings → Integrations → Webhooks")
            errors += 1
        elif r.status_code == 429:
            warn("Discord returned 429 — rate-limited. Wait a minute and retry.")
            warnings += 1
        else:
            fail(f"Discord returned {r.status_code}: {r.text[:200]}")
            errors += 1
    except requests.exceptions.ConnectionError:
        fail("Could not connect to Discord — check your internet connection.")
        errors += 1
    except requests.exceptions.Timeout:
        fail("Discord request timed out after 5 seconds.")
        errors += 1
    except Exception as e:
        fail(f"Webhook test crashed: {e}")
        errors += 1
else:
    warn("Skipping webhook test (fix errors above first).")


# ── Summary ───────────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
if errors == 0 and warnings == 0:
    print(f"{GREEN}All checks passed. Ready to run the system.{RESET}")
    print("\nNext steps:")
    print("  1. python baseline.py        (first run only — creates baseline)")
    print("  2. python monitor.py         (in one terminal)")
    print("  3. streamlit run dashboard.py (in another terminal)")
    sys.exit(0)
elif errors == 0:
    print(f"{YELLOW}Setup OK, but {warnings} warning(s). System should still run.{RESET}")
    sys.exit(0)
else:
    print(f"{RED}{errors} error(s) and {warnings} warning(s). "
          f"Fix the errors before running the system.{RESET}")
    sys.exit(1)
