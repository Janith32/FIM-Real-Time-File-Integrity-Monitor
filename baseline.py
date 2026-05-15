import os
from pathlib import Path

from dotenv import load_dotenv

from utils import db_connect, hash_file, init_all_tables, get_logger

load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env",
            override=True)

# Default to a path next to this script if MONITOR_PATH isn't set.
MONITOR_PATH = os.getenv(
    "MONITOR_PATH",
    str(Path(__file__).resolve().parent / "Web_Server_Files"))

log = get_logger("fim.baseline")


def create_baseline(folder):
    
    init_all_tables()  # ensures baseline table exists
    conn = db_connect()
    c = conn.cursor()
    count = 0
    for root, dirs, files in os.walk(folder):
        for filename in files:
            path = os.path.join(root, filename)
            try:
                file_hash = hash_file(path)
                stat = os.stat(path)
                c.execute(
                    "INSERT OR REPLACE INTO baseline VALUES (?, ?, ?, ?)",
                    (path, file_hash, stat.st_size, stat.st_mtime))
                count += 1
                log.info("Hashed: %s", path)
            except Exception as e:
                log.error("Error hashing %s: %s", path, e)
    conn.commit()
    conn.close()
    log.info("Baseline created: %d files", count)


if __name__ == "__main__":
    Path(MONITOR_PATH).mkdir(parents=True, exist_ok=True)
    log.info("Building baseline for: %s", MONITOR_PATH)
    create_baseline(MONITOR_PATH)
