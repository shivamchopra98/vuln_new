# load.py
import os
import math
import re
import time
import pandas as pd
import boto3
from decimal import Decimal, InvalidOperation
from botocore.exceptions import ClientError

# Config - adjust paths if needed
PROJECT_ROOT = r"C:\Users\ShivamChopra\Projects\vuln\epss_db"
EPSS_CSV = os.path.join(PROJECT_ROOT, "epss_extract.csv")  # <-- file to upload
DDB_ENDPOINT = "http://localhost:8000"
AWS_REGION = "us-east-1"
TABLE_NAME = "epss_data"
PROGRESS_INTERVAL = 500  # print progress every N rows

# helpers
_num_re = re.compile(r"^-?\d+(\.\d+)?$")

def is_number_string(s):
    if s is None:
        return False
    s = str(s).strip()
    return bool(_num_re.match(s))

def to_ddb_value(v):
    """
    Convert a CSV cell value to a Dynamo-friendly Python type:
     - empty / nan -> None (Dynamo doesn't accept empty string)
     - numeric-like strings -> Decimal(...)
     - otherwise keep string
    """
    if v is None:
        return None
    # pandas may give numpy.nan; treat as None
    try:
        if pd.isna(v):
            return None
    except Exception:
        pass
    s = str(v).strip()
    if s == "" or s.lower() in {"nan", "none"}:
        return None
    # numeric?
    if is_number_string(s):
        # use Decimal for Dynamo numeric
        try:
            return Decimal(s)
        except (InvalidOperation, Exception):
            return s
    return s

def connect_dynamodb():
    return boto3.resource(
        "dynamodb",
        region_name=AWS_REGION,
        aws_access_key_id="dummy",
        aws_secret_access_key="dummy",
        endpoint_url=DDB_ENDPOINT
    )

def ensure_table(ddb_resource):
    existing_tables = ddb_resource.meta.client.list_tables().get("TableNames", [])
    if TABLE_NAME not in existing_tables:
        print(f"⚡ Creating local DynamoDB table '{TABLE_NAME}' ...")
        table = ddb_resource.create_table(
            TableName=TABLE_NAME,
            KeySchema=[{"AttributeName": "cve", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "cve", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        table.meta.client.get_waiter("table_exists").wait(TableName=TABLE_NAME)
        print("✅ Table created.")
    else:
        table = ddb_resource.Table(TABLE_NAME)
        print(f"ℹ️ Table '{TABLE_NAME}' exists.")
    return ddb_resource.Table(TABLE_NAME)

def load():
    # 1) read CSV
    if not os.path.exists(EPSS_CSV):
        raise FileNotFoundError(f"EPSs CSV not found: {EPSS_CSV}")
    print(f"📄 Reading CSV: {EPSS_CSV}")
    # read as strings to avoid unintended numeric casting
    df = pd.read_csv(EPSS_CSV, dtype=str, keep_default_na=False)
    total = len(df)
    print(f"ℹ️ Rows in CSV: {total}")

    # ensure the 'cve' column exists
    if "cve" not in df.columns:
        raise ValueError("CSV must contain a 'cve' column (case-sensitive).")

    # 2) connect and ensure table
    ddb = connect_dynamodb()
    table = ensure_table(ddb)

    # 3) batch write all rows
    uploaded = 0
    start = time.time()
    with table.batch_writer(overwrite_by_pkeys=["cve"]) as batch:
        for idx, row in df.iterrows():
            # build item dict
            item = {}
            for col in df.columns:
                val = row.get(col)
                # convert to DDB friendly
                item[col] = to_ddb_value(val)
            # ensure partition key 'cve' is a string and present
            if item.get("cve") is None:
                print(f"⚠️ Skipping row {idx} missing 'cve'")
                continue
            # Dynamo requires the partition key to be a string (we can stringify if it's Decimal)
            if isinstance(item["cve"], Decimal):
                item["cve"] = str(item["cve"])
            try:
                batch.put_item(Item=item)
                uploaded += 1
            except ClientError as e:
                print(f"❌ Failed to write cve={item.get('cve')}: {e}")
            # progress
            if uploaded % PROGRESS_INTERVAL == 0:
                elapsed = time.time() - start
                print(f"⬆️ Uploaded {uploaded}/{total} rows ({elapsed:.1f}s elapsed)")

    elapsed = time.time() - start
    print(f"✅ Finished upload: {uploaded}/{total} rows uploaded in {elapsed:.1f}s")

    # optional verify: count items in table (scan)
    try:
        resp = table.meta.client.describe_table(TableName=TABLE_NAME)
        print("ℹ️ DynamoDB table status:", resp["Table"]["TableStatus"])
    except Exception:
        pass

if __name__ == "__main__":
    load()
