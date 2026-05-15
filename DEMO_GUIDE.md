# DEMO GUIDE
## Real-Time File Integrity and Security Monitoring Dashboard


## What This System Does

This is a **File Integrity Monitoring (FIM)** system for Windows. It watches a folder of website files in real time, detects any unauthorised change (creation, modification, deletion, renaming), hashes every file with SHA-256, logs every event to a tamper-evident audit chain, and automatically restores deleted files from a backup snapshot.

You can observe all of this live through a web dashboard running at `http://localhost:8501`.

---

## Setup (One Time — 5 Minutes)

### Step 1 — Install Python dependencies

Open PowerShell in the project folder and run:

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### Step 2 — Configure the environment

```powershell
copy .env.demo .env
notepad .env
```

Update **two lines only** — replace `D:\FIM_Project` with the actual path where you placed this project:

```
MONITOR_PATH=C:\Users\YourName\Desktop\FIM_Project\Web_Server_Files
BACKUP_PATH=C:\Users\YourName\Desktop\FIM_Project\Backup
```

Leave everything else as-is (Discord is disabled by default so no account is needed).

### Step 3 — Build the baseline and start the monitor

**Terminal 1:**

```powershell
.\venv\Scripts\activate
python baseline.py
python monitor.py
```

You should see:

```
[INFO] FIM System Starting
[INFO] Monitor path : ...\Web_Server_Files
[INFO] Backup folder: ...\Backup (archive only)
[INFO] Restore on DELETE: true
[INFO] Restore on MODIFY: False
[INFO] Self-integrity: ENABLED
[INFO] Watching for file system events...
```

### Step 4 — Start the dashboard

**Terminal 2 (new window):**

```powershell
.\venv\Scripts\activate
streamlit run dashboard.py --server.port 8501
```

Open **http://localhost:8501** in your browser.

### Step 5 — Log in

| Field    | Value          |
|----------|---------------|
| Username | `admin`       |
| Password | `ChangeMe123` |

> **Note:** The system forces a password change on first login. Set any password that is at least 10 characters with a letter and a digit (e.g. `Examiner2025`).

---

## Running the Demonstrations

With the monitor running and the dashboard open, launch the attack simulator in a third terminal:

```powershell
.\venv\Scripts\activate
python attack_simulator.py
```

A numbered menu appears. Run each attack in order and observe the dashboard response.

---

## Attack-by-Attack Guide

### Attack 1 — Web Defacement
**Select: option 1**

The file `Web_Server_Files/index.html` is overwritten with attacker content.

**What to observe on the dashboard (Alerts page):**
- New row appears within **2–4 seconds**
- File: `index.html`
- Event type: `MODIFIED`
- Severity: `HIGH`
- MITRE tag: `T1565.001`
- Hash-before and Hash-after columns both populated with different SHA-256 values

**Real-world meaning:** This is a web defacement attack. The FIM caught it in seconds; a human administrator checking the site manually might not notice for days.

---

### Attack 2 — Backdoor Injection
**Select: option 2**

A PHP webshell (`shell.php`) is planted in the web root — the classic method an attacker uses to maintain persistent remote access after initial compromise.

**What to observe:**
- New row within **2–4 seconds**
- File: `shell.php`
- Event type: `NEW_FILE`
- MITRE tag: `T1105`
- Severity: `HIGH` or `MEDIUM` (depends on severity rules configured)

**Tip:** Go to the **Configuration page** → Severity Rules → add a rule: pattern `.php`, severity `HIGH`. The next new PHP file will be classified HIGH automatically.

---

### Attack 3 — Ransomware Simulation
**Select: option 3**

Three files are deleted simultaneously: `about.html`, `contact.html`, `assets/style.css`.

**What to observe:**
- Three `DELETED` alerts within **2–4 seconds**, each tagged `T1070.004`
- Severity: `HIGH` for all three
- **Auto-restore:** if `AUTO_RESTORE_ON_DELETE=true` (the default), watch the deleted files **reappear in Windows Explorer within approximately 2 seconds**

**Open Windows Explorer** on the `Web_Server_Files/` folder before running this attack to see the files disappear and reappear in real time.

**What to demonstrate:**
- The alert history records the attack permanently — the attacker cannot silently undo this
- Auto-restore means the website came back online automatically
- All three events are timestamped in the audit chain

---

### Attack 4 — Audit Chain Tampering
**Select: option 4**

> Run **after attacks 1, 2 or 3** — the chain must have at least one entry.

Directly edits the `fim.db` SQLite database and corrupts a `chained_alerts` entry, simulating an attacker trying to erase evidence.

**What to observe (Chain Verify page):**
1. Click **"Verify Chain Integrity"**
2. The system reports: **TAMPER DETECTED** at the modified entry
3. Both the hash chain and the HMAC layer flag the corruption

**Why this matters:**
- A plain hash chain can be defeated if an attacker rebuilds the entire chain from scratch
- The HMAC layer prevents this — without the secret key (`FIM_HMAC_KEY` in `.env`), no valid MACs can be produced for fabricated entries
- The system correctly identifies *which entry* was altered, giving forensic precision

---

### Attack 5 — FIM Self-Tampering
**Select: option 5**

Modifies `monitor.py` while the watcher is running — simulating an attacker who modifies the monitoring script to suppress alerts for their own activity.

**What to observe:**
- Within **up to 30 seconds** (self-watcher polling interval), the **Self-Integrity page** changes status to `COMPROMISED`
- An alert appears: `MODIFIED` on `monitor.py`, severity `HIGH`, MITRE `T1562.001`

**Why this matters:**
- Most FIM tools do not watch themselves — an attacker who can write to the server could simply disable monitoring
- This system detects tampering with its own source code

**Run option 6 (Reset) immediately after to remove the modification from monitor.py.**

---

### Reset — Restore All Demo Files
**Select: option 6**

Restores `index.html`, `about.html`, `contact.html`, `style.css`, and `admin/login.php` from the `_demo_originals/` backup. Also removes `shell.php` and cleans the attacker line from `monitor.py`.

The FIM database (`fim.db`) is **not** reset — all generated alerts remain visible, which is intentional for demonstrating the accumulated audit history.

---

## Dashboard Page Reference

| Page | What to Show |
|------|-------------|
| **Dashboard** | KPI tiles (total alerts, HIGH/MEDIUM counts), severity trend chart over last 24 hours |
| **Alerts** | Full alert table — filter by severity, event type, file path; colour-coded rows |
| **Chain Verify** | Run after Attack 4 — shows tamper detection working |
| **Self-Integrity** | Run after Attack 5 — shows FIM watching its own source files |
| **Configuration** | Add/remove monitored paths; add severity rules (show .php → HIGH) |
| **User Management** | Create a second `local_user` account — show it has read-only access |
| **Log Report** | All authentication and admin actions — immutable audit trail |
| **Reports** | Generate a PDF incident report — download and open |

---

## Two-User Role Demonstration

To demonstrate role-based access control:

1. Go to **User Management** (admin only)
2. Create a new user: username `analyst1`, role `local_user`
3. Log out and log in as `analyst1`
4. Observe: Configuration, User Management, and Log Report pages are **not accessible**
5. `local_user` can only view alerts and verify the chain — read-only access

---

## Troubleshooting

| Problem | Solution |
|---------|---------|
| Files not being detected | Check that `MONITOR_PATH` in `.env` is the correct absolute path |
| Auto-restore not working | Run `python baseline.py` first — the Backup folder must be seeded |
| Chain Verify says "key not set" | Ensure `FIM_HMAC_KEY` is present in `.env` |
| Attack 4 says "chain empty" | Run attacks 1–3 first to generate alerts, then retry |
| Dashboard blank | Press `Ctrl+F5` in browser to force reload |
| Locked out of admin | Run `python unlock_admin.py` in a terminal |
| Forgot password | Run `python reset_admin.py` — recreates admin with default password |

---

## Technical Summary for Reference

| Component | Technology |
|-----------|-----------|
| File watcher | Python `watchdog` library |
| Hashing | SHA-256 via Python `hashlib` |
| Audit chain | SHA-256 hash chain + HMAC-SHA256 (dual layer) |
| Database | SQLite 3 (WAL mode) |
| Authentication | `bcrypt` cost factor 12 |
| Dashboard | `Streamlit` 1.30+ |
| PDF reports | `ReportLab` |
| Notifications | Discord webhook (rate-limited, offline queue) |
| Self-monitoring | 30-second polling of FIM source files |
| Password policy | Min 10 chars, 1 letter, 1 digit |
| Session timeout | 30 minutes idle |

---

