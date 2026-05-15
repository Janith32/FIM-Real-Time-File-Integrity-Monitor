import sqlite3
import sys

DB_PATH = "fim.db"


def main():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT MIN(id) FROM chained_alerts")
    row = c.fetchone()
    target_id = row[0] if row else None

    if target_id is None:
        print("Chain is empty. Generate some alerts first "
              "(modify a file in a monitored folder), then re-run.")
        conn.close()
        sys.exit(1)

    c.execute("UPDATE chained_alerts SET alert_data = 'HACKED' "
              "WHERE id = ?", (target_id,))
    affected = c.rowcount
    conn.commit()
    conn.close()

    if affected == 1:
        print(f"Tampered with chain entry id={target_id}.")
        print("Now run 'Verify Chain Integrity' in the dashboard — "
              "it should report tampering.")
    else:
        print(f"Unexpected: UPDATE affected {affected} rows. "
              "Check the database.")
        sys.exit(2)


if __name__ == "__main__":
    main()
