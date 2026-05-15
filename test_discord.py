import os
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv


def main():
    # .env lives next to this script.
    env_path = Path(__file__).resolve().parent / ".env"
    load_dotenv(dotenv_path=env_path, override=True)

    webhook_url = os.getenv("DISCORD_WEBHOOK_URL", "")

    if not webhook_url or webhook_url == "PASTE_YOUR_WEBHOOK_URL_HERE":
        print("ERROR: DISCORD_WEBHOOK_URL is not set in your .env file.")
        print(f"  Looked at: {env_path}")
        print("  Copy .env.example to .env and add your webhook URL.")
        sys.exit(1)

    print("Testing Discord webhook...")
    print(f"URL: {webhook_url[:60]}...")

    try:
        response = requests.post(
            webhook_url,
            json={"content": "Test from FIM project"},
            timeout=10)
        print(f"Status code: {response.status_code}")
        print(f"Response text: {response.text}")
        if response.status_code == 204:
            print("SUCCESS - check your Discord channel")
        else:
            print(f"FAILED - Discord returned {response.status_code}")
    except Exception as e:
        print(f"ERROR: {e}")


if __name__ == "__main__":
    main()
