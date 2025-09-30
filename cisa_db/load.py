# load_cisa.py
import os
import json
import time
import math
import boto3
from decimal import Decimal
from botocore.exceptions import ClientError

# Default config (can be overridden by caller)
DEFAULT_CONFIG = {
    "TABLE_NAME": "cisa_data",
    "DDB_ENDPOINT": "http://localhost:8000",
    "AWS_REGION": "us-east-1",
    "PROJECT_ROOT": r"C:\Users\ShivamChopra\Projects\vuln\metasploit_db",  # will be overridden by caller
    "DAILY_DIR": None,  # resolved relative to PROJECT_ROOT if None
    "BASELINE_FILENAME": "cisa_extract.json",
    "BATCH_PROGRESS_SIZE": 25
}

def _resolve_config(user_config):
    cfg = DEFAULT_CONFIG.copy()
    if user_config:
        cfg.update(user_config)
    if not cfg["DAILY_DIR"]:
        cfg["DAILY_DIR"] = os.path.join(cfg["PROJECT_ROOT"], "daily_extract")
    cfg["BASELINE_FILE"] = os.path.join(cfg["DAILY_DIR"], cfg["BASELINE_FILENAME"])
    return cfg

def get_dynamodb_table(cfg):
    ddb = boto3.resource(
        "dynamodb",
        region_name=cfg["AWS_REGION"],
        aws_access_key_id="dummy",
        aws_secret_access_key="dummy",
        endpoint_url=cfg["DDB_ENDPOINT"],
    )
    existing = ddb.meta.client.list_tables().get("TableNames", [])
    if cfg["TABLE_NAME"] not in existing:
        print(f"⚡ Creating DynamoDB table '{cfg['TABLE_NAME']}' locally...")
        table = ddb.create_table(
            TableName=cfg["TABLE_NAME"],
            KeySchema=[{"AttributeName": "cveID", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "cveID", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
        )
        table.meta.client.get_waiter("table_exists").wait(TableName=cfg["TABLE_NAME"])
        print("✅ Table created.")
    return ddb.Table(cfg["TABLE_NAME"])

def remove_dated_jsons_keep_baseline(daily_dir, baseline_file):
    """Delete dated JSON files except baseline_file (and any other .json that is not baseline)."""
    baseline_name = os.path.basename(baseline_file)
    for fname in os.listdir(daily_dir):
        if fname == baseline_name:
            continue
        if fname.endswith(".json"):
            p = os.path.join(daily_dir, fname)
            try:
                os.remove(p)
                print(f"🗑️ Deleted stray JSON: {p}")
            except Exception:
                pass

def load_json_to_map(path):
    """Load list-of-dicts JSON into {cveID: record} map."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    m = {}
    for rec in data:
        cid = rec.get("cveID")
        if not cid:
            continue
        m[str(cid).strip()] = rec
    return m

def items_equal(rec_a, rec_b):
    """Shallow comparison ignoring 'uploaded_date' (treated as meta)."""
    if rec_b is None:
        return False
    for k, v in rec_a.items():
        if k == "uploaded_date":
            continue
        va = rec_a.get(k)
        vb = rec_b.get(k)
        if va != vb:
            return False
    return True

def sync_today_with_dynamodb(current_json_path: str, config: dict = None):
    """
    Sync the transformed CISA JSON (list of records) with DynamoDB.
    - compares current JSON vs baseline JSON (cisa_extract.json) to find changed/new cveIDs
    - also detects baseline cveIDs missing in DynamoDB and re-adds them
    - writes only real differences into DynamoDB (per-item get + batch put)
    - overwrites baseline JSON with current data and deletes stray dated JSONs
    Returns summary dict.
    """
    cfg = _resolve_config(config)
    DAILY_DIR = cfg["DAILY_DIR"]
    BASELINE_FILE = cfg["BASELINE_FILE"]
    TABLE_NAME = cfg["TABLE_NAME"]
    batch_size = cfg["BATCH_PROGRESS_SIZE"]

    os.makedirs(DAILY_DIR, exist_ok=True)
    table = get_dynamodb_table(cfg)

    # load current transformed JSON (list)
    current_map = load_json_to_map(current_json_path)
    total_current = len(current_map)
    print(f"ℹ️ Loaded current transformed records: {total_current}")

    # load baseline if present
    baseline_exists = os.path.exists(BASELINE_FILE)
    baseline_map = {}
    if baseline_exists:
        baseline_map = load_json_to_map(BASELINE_FILE)
        print(f"ℹ️ Baseline exists with {len(baseline_map)} records")
    else:
        print("ℹ️ No baseline found (first run)")

    # compute changed_ids (new or differing vs baseline)
    changed_ids = []
    for cid, rec in current_map.items():
        base_rec = baseline_map.get(cid)
        if base_rec is None:
            changed_ids.append(cid)
        else:
            if not items_equal(rec, base_rec):
                changed_ids.append(cid)

    # also check baseline ids missing from DDB (re-add accidental deletions)
    missing_in_ddb = []
    if baseline_exists:
        for cid in baseline_map.keys():
            try:
                resp = table.get_item(Key={"cveID": cid})
                if "Item" not in resp:
                    missing_in_ddb.append(cid)
            except ClientError:
                missing_in_ddb.append(cid)
    # combine
    for mid in missing_in_ddb:
        if mid not in changed_ids:
            changed_ids.append(mid)

    if not changed_ids:
        print("✅ No new/updated records and no missing baseline items in DynamoDB.")
    else:
        print(f"ℹ️ Tot changed/missing to consider: {len(changed_ids)}")

    # Prepare writes: for each changed_id compare with DDB item and only write if different or missing
    to_write = []
    for cid in changed_ids:
        rec = current_map.get(cid) or baseline_map.get(cid)
        if rec is None:
            continue
        # fetch existing DDB item
        try:
            resp = table.get_item(Key={"cveID": cid})
            ddb_item = resp.get("Item")
        except ClientError as e:
            print(f"⚠️ Warning fetching cveID={cid} from DDB: {e}")
            ddb_item = None

        if ddb_item is None:
            to_write.append(rec)
        else:
            if not items_equal(rec, ddb_item):
                to_write.append(rec)
            else:
                pass

    # Batch write to DynamoDB in manageable chunks
    uploaded = 0
    if to_write:
        print(f"⬆️ Writing {len(to_write)} items to DynamoDB...")
        # batch_writer can accept dicts directly; ensure no empty strings etc.
        with table.batch_writer(overwrite_by_pkeys=["cveID"]) as batch:
            for rec in to_write:
                # clean item: remove empty strings
                safe_item = {}
                for k, v in rec.items():
                    if isinstance(v, str) and v.strip() == "":
                        safe_item[k] = None
                    else:
                        safe_item[k] = v
                safe_item["cveID"] = str(safe_item["cveID"])
                try:
                    batch.put_item(Item=safe_item)
                    uploaded += 1
                except ClientError as e:
                    print(f"❌ Failed to write cveID={safe_item.get('cveID')}: {e}")
                if uploaded % batch_size == 0 or uploaded == len(to_write):
                    print(f"⬆️ Uploaded {uploaded}/{len(to_write)}")
    else:
        print("ℹ️ Nothing to write to DynamoDB.")

    # Overwrite baseline with current authoritative data (atomic replace)
    try:
        abs_in = os.path.abspath(current_json_path)
        abs_base = os.path.abspath(BASELINE_FILE)
        if abs_in != abs_base:
            os.replace(current_json_path, BASELINE_FILE)
        else:
            # already baseline path; ensure it is written (already is)
            pass
        print(f"✅ Baseline updated: {BASELINE_FILE}")
    except Exception as e:
        print(f"❌ Failed to update baseline: {e}")
        raise

    # Remove other dated JSONs in the daily dir (keep only baseline)
    remove_dated_jsons_keep_baseline(DAILY_DIR, BASELINE_FILE)

    # summary
    summary = {
        "total_current": total_current,
        "changed_ids_considered": len(changed_ids),
        "to_write": len(to_write),
        "uploaded": uploaded,
        "baseline_file": BASELINE_FILE,
        "table": TABLE_NAME
    }
    print("✅ Sync summary:", summary)
    return summary
