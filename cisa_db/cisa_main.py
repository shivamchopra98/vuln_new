# cisa_main.py
from extract import download_raw_json
from transform import transform_json
from load import sync_today_with_dynamodb
import os

RAW_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# <-- UPDATED to point at your CISA project folder
PROJECT_ROOT = r"C:\Users\ShivamChopra\Projects\vuln\cisa_db"
DAILY_DIR = os.path.join(PROJECT_ROOT, "daily_extract")

CISA_CONFIG = {
    "TABLE_NAME": "cisa_data",
    "DDB_ENDPOINT": "http://localhost:8000",
    "AWS_REGION": "us-east-1",
    "PROJECT_ROOT": PROJECT_ROOT,
    "DAILY_DIR": DAILY_DIR,
    "BASELINE_FILENAME": "cisa_extract.json",
    "BATCH_PROGRESS_SIZE": 25
}

def main():
    # 1) extract
    try:
        raw_path = download_raw_json(RAW_JSON_URL, DAILY_DIR)
    except Exception as e:
        print(f"❌ Download failed: {e}")
        return

    # 2) transform (normalize fields we need)
    try:
        transformed_path = transform_json(raw_path)
    except Exception as e:
        print(f"❌ Transformation failed: {e}")
        return

    # 3) load/sync
    try:
        res = sync_today_with_dynamodb(transformed_path, config=CISA_CONFIG)
        print("✅ Sync result:", res)
    except Exception as e:
        print(f"❌ Load/sync failed: {e}")
        return

if __name__ == "__main__":
    main()
