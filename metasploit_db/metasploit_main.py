# metasploit_main.py
import os
from dotenv import load_dotenv

load_dotenv()

from extract import download_raw_json_to_text
from transform import transform_json_text_to_records_and_json_bytes
from load import sync_records_to_dynamodb_and_store_baseline

RAW_JSON_URL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"

METASPLOIT_CONFIG = {
    "TABLE_NAME": os.getenv("METASPLOIT_TABLE", "metasploit_data"),
    "DDB_ENDPOINT": os.getenv("DDB_ENDPOINT", "http://localhost:8000"),
    "AWS_REGION": os.getenv("AWS_REGION", "us-east-1"),
    "S3_BUCKET": os.getenv("S3_BUCKET"),
    "S3_PREFIX": os.getenv("S3_PREFIX", "vuln-raw-source/metasploit/"),
    "BASELINE_FILENAME": os.getenv("BASELINE_FILENAME", "metasploit_baseline.json"),
    "CANONICAL_FILENAME": os.getenv("CANONICAL_FILENAME", "metasploit.json"),
    "AWS_ACCESS_KEY_ID": os.getenv("AWS_ACCESS_KEY_ID"),
    "AWS_SECRET_ACCESS_KEY": os.getenv("AWS_SECRET_ACCESS_KEY"),
    "BATCH_PROGRESS_INTERVAL": int(os.getenv("BATCH_PROGRESS_INTERVAL", "100"))
}

def main():
    print("▶️ Starting Metasploit ETL (in-memory, JSON-based)")
    if not METASPLOIT_CONFIG["S3_BUCKET"]:
        raise RuntimeError("S3_BUCKET must be set in environment or .env")

    raw_text = download_raw_json_to_text(RAW_JSON_URL)
    records, json_bytes = transform_json_text_to_records_and_json_bytes(raw_text)
    summary = sync_records_to_dynamodb_and_store_baseline(records, json_bytes, METASPLOIT_CONFIG)
    print("✅ ETL finished.")
    return summary

if __name__ == "__main__":
    main()
