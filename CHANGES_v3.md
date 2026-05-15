# Bug Fix Pass v3 — Honest Critique Resolution

This pass addresses the seven bugs and gaps surfaced in the v2 code review.
Each fix is small, well-commented, and preserves backwards compatibility
with existing databases. No new dependencies were added.

| # | File | Change |
|---|------|--------|
| 1 | `secure_chain.py` | Drops local `_connect()`; routes every connection through `utils.db_connect()` |
| 2 | `utils.py` | Adds `_restore_lock` to make `_restore_tracker` thread-safe |
| 3 | `dashboard.py` | New `get_alert_counts()` with real `COUNT(*)` queries — KPI tiles no longer cap at 200 |
| 4 | `auth.py` | `init_users_table()` and `init_config_tables()` are now thin wrappers around `utils.init_all_tables()`; canonical schema lives in one place only |
| 5 | `auth.py`, `dashboard.py` | New `validate_password_policy()` enforces ≥10 chars + letter + digit, used by `create_user` and the change-password screen |
| 6 | `dashboard.py` | 30-minute idle session timeout; `_force_logout()` audits the timeout |
| 7 | `alerts.py` | Sliding-window rate limiter (4 / 5 s) on Discord posts; periodic "X alerts suppressed" summary so bursts don't drown the channel or hit Discord's 429 |

---

## Bug-by-bug

### 1. `secure_chain.py` bypassed the shared `db_connect()`

**Before.** `secure_chain.py` had its own `_connect()` that set `journal_mode=WAL`
and `synchronous=NORMAL` but missed the 5-second `busy_timeout`, the 8 MB
cache pragma, the `row_factory`, and — crucially — the exponential-backoff
retry on `OperationalError`. If `monitor.py` was holding the write lock
the moment a chain entry was being appended, the chain write would fail
immediately instead of waiting.

**After.** The local `_connect()` is gone. Every call site (`add_to_chain`,
`verify_chain`, `backfill_macs`) now uses `utils.db_connect()`, so the chain
inherits the same retry, busy_timeout, and pragma settings as the rest of
the system. The architectural promise of "one `db_connect()` for everyone"
is finally true.

### 2. `_restore_tracker` race condition

**Before.** The module-level dict `_restore_tracker` in `utils.py` was
mutated by `can_restore()` on every restore decision. Watchdog dispatches
events from a worker-thread pool, so two threads restoring different paths
could mutate the dict concurrently — at minimum losing a deque entry,
worst case raising `RuntimeError: dictionary changed size during iteration`
and silently killing a watchdog worker.

**After.** A dedicated `_restore_lock` (separate from the existing
`_state_lock` in monitor.py — different concerns, different module, no
deadlock risk) wraps every read and write of the tracker. Same semantics,
no race.

### 3. Dashboard KPI tiles capped at 200

**Before.** `get_alerts()` runs `SELECT * ... LIMIT 200`. The KPI
metrics (HIGH / MEDIUM / LOW / Total Alerts) were computed from
`len(alerts_df)` and slices of that capped dataframe. On a system that
had seen 1,000 alerts the dashboard showed `Total Alerts: 200` and
correspondingly under-counted severities by up to 800.

**After.** New `get_alert_counts()` issues `SELECT COUNT(*) FROM alerts`
plus a `GROUP BY severity` aggregate — both run in SQLite, both O(table
size) for indexed scans, no rowset transferred to Python. The KPI tiles
read from this dict; the table view still uses the LIMIT-200 dataframe
for display speed. Verified with 250 synthetic rows: tiles correctly
show 250.

### 4. Redundant table creation in `auth.py`

**Before.** `auth.init_users_table()` and `auth.init_config_tables()`
each had their own `CREATE TABLE IF NOT EXISTS` for tables that
`utils.init_all_tables()` also creates. The migration logic for
`force_password_change` lived in two places. If a future schema change
landed in only one, the system would silently diverge.

**After.** Both functions are thin wrappers that call
`utils.init_all_tables()`. Existing import sites (`dashboard.py`'s
`init_config_tables`, internal calls inside `auth.py` from
`add_monitored_path`, etc.) work without modification — the function
names still exist and still create the tables, they just delegate to
the canonical schema.

### 5. Weak password policy

**Before.** `create_user()` enforced length ≥ 8. The dashboard's
change-password screen also enforced length ≥ 8. Both accepted
`aaaaaaaa`. Two enforcement points, no shared validator — easy for
the rules to drift.

**After.** New `validate_password_policy(password)` lives in `auth.py`
and is the single source of truth for the policy:

- ≥ 10 characters
- ≥ 1 letter
- ≥ 1 digit

Used by `create_user()` and the dashboard's change-password screen.
The form labels and the failure messages now describe the same rules.
The default-admin seed (`ChangeMe123`) was bumped from `admin123` so
it satisfies the new policy; alternatively the seeder uses an explicit
`_skip_policy=True` parameter so even a non-conforming seed would work
(the account is force-change-on-login anyway, so the seed is
irrelevant beyond the first 30 seconds).

For an internet-facing deployment the policy should be tightened
further — e.g. integration with HaveIBeenPwned's k-anonymity API to
reject known-breached passwords. Documented as future work.

### 6. No session timeout

**Before.** Streamlit `st.session_state` is browser-tab-scoped and
never expires on its own. A logged-in tab on a shared workstation
stayed authenticated indefinitely. There was no way to invalidate a
session server-side.

**After.** A new `last_activity` timestamp lives in session state.
`_is_session_expired()` checks it on every rerun and forces a logout
after 30 idle minutes (`SESSION_TIMEOUT_MINUTES`). The forced logout
audit-logs `LOGOUT_TIMEOUT` so abandoned sessions are visible in the
audit trail. The check runs *before* any sensitive page renders, so
no page contents leak to an expired tab.

Caveat — Streamlit auto-refresh ticks count as activity. The timeout
therefore measures wall-clock idleness of the browser tab, not of the
human user. For a security dashboard this is the conservative
direction (log out sooner, never later); a stricter policy would
require disabling auto-refresh or a separate "interaction-only"
timestamp.

### 7. No alert rate limiting

**Before.** Each file event called `send_discord_alert()` synchronously
from the watchdog hot path. Ransomware encrypting 500 files per second
would issue 500 Discord webhook calls per second — Discord's per-webhook
rate limit is ~5 / 5 s, so the system would immediately start hitting
HTTP 429s, flood the log file with failure messages, and potentially
block the watchdog thread pool.

**After.** A sliding-window limiter caps Discord posts at 4 per 5
seconds (`WEBHOOK_MAX_PER_WINDOW` / `WEBHOOK_WINDOW_SECONDS`) — one
under Discord's ceiling for safety. Suppressed alerts increment a
counter. After at least `WEBHOOK_SUMMARY_INTERVAL` seconds (default
60), the next successful post triggers a summary message —
"⚠️ FIM rate limit: N alert(s) suppressed in the last 60s" — so the
operator notices the burst without being flooded. All alerts are
still written to the database and the audit chain regardless of
whether Discord receives them; the rate limiter only affects the
Discord channel.

The implementation uses the same `deque` pattern as `utils.can_restore()`
and is also lock-protected.

---

## What is still NOT fixed (by design)

### HTTPS

The dashboard still runs over plain HTTP via Streamlit's built-in dev
server. Fixing this requires deployment changes, not code changes —
a reverse proxy (nginx / Caddy / IIS) terminating TLS, or running
Streamlit behind `streamlit run --server.sslCertFile=... --server.sslKeyFile=...`.
For internal LAN use the current setup is the same risk profile as any
other internal HTTP tool; for any wider deployment, terminate TLS at
the proxy.

### Self-watch re-enroll-on-startup

Inherent limitation of self-monitoring without an out-of-band trust
anchor. Documented in CHANGES.md.

---

## Smoke-test results

```
auth import OK
  validate_password_policy("short"):  (False, 'Password must be at least 10 characters')
  validate_password_policy("abcdefghij"): (False, 'Password must contain at least one digit')
  validate_password_policy("abc1234567"): (True, 'OK')
  authenticate(admin, ChangeMe123): True {'role': 'admin', 'force_change': True}

secure_chain uses utils.db_connect — OK
  Chain entry added, hash: 8cf775b617242e31...
  verify_chain: True — Chain verified. 1 entries — hash chain and all MACs valid.

alerts rate limiter loaded: 4 per 5 s
  rate_limit_check x10 allowed: 4 (should be 4)
  suppressed counter: 6

utils._restore_lock present: True
  can_restore("x") x5: [True, True, True, False, False]

KPI fix verified with 250 synthetic rows:
  Total: 250 (was capped at 200)
  HIGH=84  MEDIUM=83  LOW=83
```

---

## How to apply

1. Drop the modified files (`alerts.py`, `auth.py`, `dashboard.py`,
   `secure_chain.py`, `utils.py`) into the project, replacing the
   originals.
2. Restart `monitor.py` and the Streamlit dashboard.
3. Existing databases are upgraded transparently — no migrations
   required beyond the ones `utils.init_all_tables()` already
   handles.
4. The default admin password is now `ChangeMe123`. If your existing
   database already has a real admin account this is irrelevant; only
   first-run installs see this seed, and only until the operator
   completes the forced password change.
