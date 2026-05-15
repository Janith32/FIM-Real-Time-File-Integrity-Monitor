from utils import db_connect

conn = db_connect()
c = conn.cursor()

c.execute("DELETE FROM users WHERE username='admin'")
users_deleted = c.rowcount
c.execute("DELETE FROM audit_log WHERE username='admin'")
audit_deleted = c.rowcount

conn.commit()
conn.close()

print(f"Removed {users_deleted} admin user, {audit_deleted} audit rows.")
print("Restart the dashboard. If the users table is now empty,")
print("init_default_admin() will recreate admin / ChangeMe123.")