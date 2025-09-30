# metasploit_main.py
import os
from extract import download_raw_json
from transform import transform_json
from load import sync_today_with_dynamodb

RAW_JSON_URL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
PROJECT_ROOT = r"C:\Users\ShivamChopra\Projects\vuln\metasploit_db"
DAILY_DIR = os.path.join(PROJECT_ROOT, "daily_extract")

METASPLOIT_CONFIG = {
    "TABLE_NAME": "metasploit_data",
    "DDB_ENDPOINT": "http://localhost:8000",
    "AWS_REGION": "us-east-1",
    "PROJECT_ROOT": PROJECT_ROOT,
    "DAILY_DIR": DAILY_DIR,
    "BASELINE_FILENAME": "metasploit_baseline.csv",
    "BATCH_PROGRESS_INTERVAL": 100
}

def main():
    try:
        json_path = download_raw_json(RAW_JSON_URL, DAILY_DIR)
    except Exception as e:
        print(f"❌ Download failed: {e}")
        return

    try:
        csv_path = transform_json(json_path)
    except Exception as e:
        print(f"❌ Transformation failed: {e}")
        return

    try:
        result = sync_today_with_dynamodb(csv_path, config=METASPLOIT_CONFIG)
        print("✅ Sync finished.")
    except Exception as e:
        print(f"❌ Load/sync failed: {e}")
        return

if __name__ == "__main__":
    main()
