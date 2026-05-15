# Real-Time File Integrity and Security Monitoring Dashboard

A Windows-based, locally-hosted file integrity monitor (FIM) with a
web dashboard. Watches a configured folder in real time, hashes every
file at enrolment, detects modification / deletion / creation / rename
events, classifies them by MITRE ATT&CK technique and severity, writes
each event to a tamper-evident HMAC-protected audit chain, and
optionally pushes alerts to Discord. A self-integrity monitor watches
the FIM's own source files so that disabling the monitor itself
triggers a HIGH-severity alert.

Designed for small-business deployments where commercial FIM tools
(Tripwire, OSSEC, Sysmon) are either too expensive or too operationally
complex.

---

## Quick start (5 minutes)

### 1. Prerequisites

- **Python 3.10 or newer** (developed on 3.12). Verify with `python --version`.
- **Windows 10/11** for full functionality. The code is mostly cross-platform but the atomic-save event correlation, NTFS path handling, and self-watcher path lookups were tested on Windows.
- **A Discord webhook URL** (optional — alerts still appear in the dashboard if Discord is disabled).

### 2. Install

```powershell
# From an empty folder
git clone <repo-url> FIM_Project
cd FIM_Project

# Create and activate a venv
python -m venv venv
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure

Copy the example environment file and edit it:

```powershell
copy .env.example .env
notepad .env
```

Fill in at minimum:

| Variable | What it does |
|---|---|
| `DISCORD_WEBHOOK_URL` | Your Discord webhook (or leave default; set `DISCORD_ENABLED=false` to disable) |
| `MONITOR_PATH` | Absolute path of the folder you want to watch, e.g. `D:\FIM_Project\Web_Server_Files` |
| `BACKUP_PATH` | Where the original-snapshot archive lives, e.g. `D:\FIM_Project\Backup` |
| `FIM_HMAC_KEY` | Secret key for HMAC chain signing — generate with `python secure_chain.py --key` |
| `AUTO_RESTORE_ON_DELETE` | Default `true`; keeps an archive of deleted files in `BACKUP_PATH` |
| `AUTO_RESTORE_ON_MODIFY` | Default `false`; if `true`, modifications get reverted from backup |

### 4. First run

The FIM runs as **two separate processes** — one watcher, one dashboard.

**Terminal 1 — start the file watcher:**

```powershell
.\venv\Scripts\activate
python baseline.py     # one-time: enrol everything in MONITOR_PATH
python monitor.py      # start watching
```

On first launch you'll see something like:

```
[INFO] Initialising all database tables in fim.db
[INFO] Default admin created (username: admin, password: ChangeMe123)
[INFO] FIM System Starting
[INFO] Backup folder    : D:\FIM_Project\Backup (archive only)
[INFO] Restore on DELETE: false (backup preserved as archive)
[INFO] Restore on MODIFY: False
[INFO] Self-integrity   : ENABLED
```

**Terminal 2 — start the dashboard:**

```powershell
.\venv\Scripts\activate
streamlit run dashboard.py --server.port 8501
```

Open <http://localhost:8501> in your browser. Log in with the default
admin credentials shown in the monitor's startup output. **You will be
forced to change the password on first login.**

### 5. Try it

With the dashboard logged in and the monitor running:

1. Drop a file into your `MONITOR_PATH` folder. Within seconds the
   dashboard's **Alerts** page shows a `NEW_FILE` event tagged with
   MITRE T1105.
2. Modify the file (open it in Notepad, edit, save). You'll see a
   single `MODIFIED` event tagged T1565.001.
3. Delete the file. You'll see `DELETED` tagged T1070.004. The copy in
   `BACKUP_PATH` is preserved as evidence.
4. Click **Chain Verify** → **Verify Chain Integrity**. You should see
   *"Chain verified. N entries — hash chain and all MACs valid."*

### 6. Run the test suite (optional)

```powershell
python tests\test_security.py
```

Three tests run, each proving one of the system's security properties:

- The HMAC chain catches tampering with a past entry
- The login lockout triggers at exactly 5 failed attempts
- The auto-restore throttle caps at 3 within 60 seconds

You can also run via pytest:

```powershell
python -m pytest tests\ -v
```

---

## What it actually does

A typical event lifecycle:

1. A file is written, modified, deleted, or renamed inside `MONITOR_PATH`
2. Watchdog dispatches an event to `monitor.py`
3. The event is debounced and correlated against atomic-save patterns
   (Office, image editors, text editors all save differently — the
   monitor distinguishes a single logical "save" from a delete-and-
   replace attack with 750 ms event correlation)
4. The file is hashed (SHA-256) and compared against the baseline
5. Severity is classified — defaults are HIGH for DELETED/MODIFIED,
   MEDIUM for NEW_FILE/RENAMED, plus admin-configurable rules
6. MITRE technique is attached (T1565.001 for modification,
   T1070.004 for deletion, T1105 for new file, T1036 for rename)
7. Event is written to the `alerts` table AND to the `chained_alerts`
   table (each entry is hashed-chained to the previous AND
   HMAC-signed with a key from `.env`)
8. Discord webhook is fired (rate-limited; queued and replayed
   automatically if Discord is unreachable)

---

## Project structure

```
.
├── monitor.py           # The file watcher. Long-running process. ⭐
├── dashboard.py         # 8-page Streamlit web UI. ⭐
├── baseline.py          # One-shot: hash everything in MONITOR_PATH and store as the trusted snapshot.
│
├── auth.py              # Bcrypt hashing, account lockout, RBAC, audit log.
├── secure_chain.py      # HMAC-SHA256-protected hash-chained audit log. (--key, --backfill, default verify)
├── alerts.py            # Discord webhook + rate limiter + offline-replay queue.
├── selfwatch.py         # Background thread hashing FIM source files every 30 s.
├── report.py            # PDF report generator (4-page security incident report).
├── utils.py             # db_connect (WAL+retry), hash_file, can_restore rate-limiter, schema migrations.
│
├── tests/
│   └── test_security.py # Three security-property tests (chain, lockout, restore throttle).
│
├── tamper_test.py       # Demo: corrupt an existing chain entry to show verify catches it.
├── test_discord.py      # Demo: send a sample alert through the Discord pipeline.
├── reset_admin.py       # Recovery: delete the admin row so init_default_admin recreates it.
├── unlock_admin.py      # Recovery: clear failed-login records to break a lockout.
├── hash_test.py         # Smoke test: hash a single file from the command line.
│
├── requirements.txt     # Dependencies.
├── .env.example         # Template; copy to .env and fill in.
├── .gitignore           # Keeps .env, fim.db, fim.log, venv/ out of version control.
├── README.md            # This file.
└── CHANGES_v3.md        # Engineering log — the bugs found in self-review and the fixes applied.
```

⭐ = the two long-running processes you start to use the system.

---

## Dashboard pages

| Page | Purpose |
|---|---|
| **Dashboard** | At-a-glance KPIs, severity breakdown, MITRE distribution chart |
| **Alerts** | All recent alerts in a filterable table; Discord offline-queue status banner |
| **Reports** | Generate a 4-page PDF security incident report |
| **Configuration** | Monitored paths, severity rules (admin only) |
| **User Management** | Create / delete users, change roles (admin only) |
| **Log Report** | Audit trail of all authentication and admin actions |
| **Chain Verify** | Run the two-pass chain verification (hash chain + HMAC) |
| **Self-Integrity** | Status of the FIM watching its own source files |

---

## Security model — what's defended, what isn't

The threat model assumes a non-admin attacker has gained access to the
host (e.g. via a compromised web app or stolen low-privilege
credentials). Within that model:

**Defended:**
- Direct file modification → SHA-256 mismatch + alert
- File deletion / replacement → event logged + backup preserved
- Atomic-save false positives → correlated with 750 ms event window
- Audit log tampering → hash chain breaks, MAC verification fails
- Wholesale chain replacement → MAC fails (attacker lacks the key)
- Brute-force login → 5-attempt sliding-window lockout
- Username enumeration via timing → constant-time dummy-hash verification
- FIM source-code modification → self-watcher fires a HIGH alert
- Discord downtime → alerts queued in SQLite, replayed on recovery


---

## Troubleshooting

**The monitor logs "Backup folder ... archive only" but the folder is empty.**
Run `python baseline.py` once. It walks `MONITOR_PATH` and copies every
file into the backup mirror.

**I can't log in — got locked out testing.**
Run `python unlock_admin.py`. This clears the failed-login window
without touching anything else.

**Forgot my admin password.**
Run `python reset_admin.py`. This deletes the admin row; on the next
dashboard launch `init_default_admin()` recreates it with the default
credentials and the force-password-change flag set.

**Chain Verify says "FIM_HMAC_KEY is not set".**
Generate a key: `python secure_chain.py --key`. Paste the 64-character
hex output into `.env` as `FIM_HMAC_KEY=<value>`. Restart the monitor.
If you have existing unsigned chain entries, also run
`python secure_chain.py --backfill`.

**Discord alerts not arriving.**
Check `DISCORD_ENABLED=true` in `.env` and that `DISCORD_WEBHOOK_URL`
is correct. If Discord is genuinely down, the Alerts page shows a
*"📡 Discord offline queue: N pending"* banner — queued alerts replay
automatically when connectivity returns.

**The dashboard loads but pages are blank.**
Streamlit caches aggressively. Clear with Ctrl+F5 in your browser, or
stop the dashboard process and restart it.

---

## Notes for evaluators

- The default admin credentials are `admin` / `ChangeMe123`. The
  account is flagged for forced password change on first login — you
  cannot use the system without setting a new password first.
- The codebase is ~5,200 lines across 17 modules. The two largest
  files are `monitor.py` (file watcher, ~840 lines) and `dashboard.py`
  (Streamlit UI, ~1,140 lines).
- The audit chain in `chained_alerts` and the alerts table in `alerts`
  are linked but separate: `alerts` is the rich query target for the
  dashboard, `chained_alerts` is the tamper-evident integrity record.
- `tamper_test.py` deliberately corrupts a chain entry to demonstrate
  that `verify_chain()` catches it — run it and then click "Verify
  Chain Integrity" on the dashboard to see the protection working.
- The Engineering log in `CHANGES_v3.md` records every bug found in
  self-review and the fix applied — including the original
  bypass-of-the-shared-connection-layer issue in `secure_chain.py`,
  the `_restore_tracker` race condition, and the password-policy
  enforcement gap.
