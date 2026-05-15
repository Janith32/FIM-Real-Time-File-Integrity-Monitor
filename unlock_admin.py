from utils import db_connect

conn = db_connect()
c = conn.cursor()

# Clear failed login attempts so the lockout window resets
c.execute("DELETE FROM audit_log "
          "WHERE username='admin' AND action='LOGIN_FAILED'")
n = c.rowcount
conn.commit()
conn.close()

print(f"Cleared {n} failed-login records. You can log in again now.")