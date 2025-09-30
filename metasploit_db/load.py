# load.py
import os
import re
import math
import time
import json
import pandas as pd
import boto3
from decimal import Decimal, InvalidOperation
from botocore.exceptions import ClientError
from datetime import datetime

# Default config (can be overridden by caller)
DEFAULT_CONFIG = {
    "TABLE_NAME": "metasploit_data",
    "DDB_ENDPOINT": "http://localhost:8000",
    "AWS_REGION": "us-east-1",
    "PROJECT_ROOT": r"C:\Users\ShivamChopra\Projects\vuln\metasploit_db",
    "DAILY_DIR": None,  # resolved relative to PROJECT_ROOT if None
    "BASELINE_FILENAME": "metasploit_baseline.csv",
    "BATCH_PROGRESS_INTERVAL": 100
}

META_ID_PREFIX = "META"

# ---------- Helpers ----------
def _resolve_config(user_config):
    cfg = DEFAULT_CONFIG.copy()
    if user_config:
        cfg.update(user_config)
    if not cfg["DAILY_DIR"]:
        cfg["DAILY_DIR"] = os.path.join(cfg["PROJECT_ROOT"], "daily_extract")
    cfg["BASELINE_FILE"] = os.path.join(cfg["DAILY_DIR"], cfg["BASELINE_FILENAME"])
    return cfg

def ensure_daily_dir(daily_dir):
    os.makedirs(daily_dir, exist_ok=True)

def connect_dynamodb(cfg):
    return boto3.resource(
        "dynamodb",
        region_name=cfg["AWS_REGION"],
        aws_access_key_id="dummy",
        aws_secret_access_key="dummy",
        endpoint_url=cfg["DDB_ENDPOINT"],
    )

def create_table_if_missing(ddb_resource, table_name):
    existing = ddb_resource.meta.client.list_tables().get("TableNames", [])
    if table_name not in existing:
        print(f"⚡ Creating DynamoDB table '{table_name}' locally...")
        table = ddb_resource.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        table.meta.client.get_waiter("table_exists").wait(TableName=table_name)
        print("✅ Table created.")
    return ddb_resource.Table(table_name)

def normalize_value(v):
    """Normalize values for stable comparison; ignore uploaded_date in comparisons."""
    if v is None:
        return None
    try:
        if pd.isna(v):
            return None
    except Exception:
        pass
    if isinstance(v, Decimal):
        return str(v)
    if isinstance(v, float):
        if math.isnan(v) or math.isinf(v):
            return None
        s = str(v)
        return s[:-2] if s.endswith(".0") else s
    s = str(v).strip()
    if s == "" or s.lower() in {"nan", "none"}:
        return None
    return s

def normalize_row_for_compare(d):
    return {k: normalize_value(v) for k, v in d.items() if k != "uploaded_date"}

def rows_differ(csv_row_dict, ddb_item_dict):
    return normalize_row_for_compare(csv_row_dict) != normalize_row_for_compare(ddb_item_dict)

def remove_dated_csvs_keep_baseline(daily_dir, baseline_file):
    """
    Remove dated CSV files in daily_dir except baseline_file.
    Also remove stray CSVs not equal to baseline (defensive).
    """
    baseline_name = os.path.basename(baseline_file)
    pattern = re.compile(r"^\d{4}-\d{2}-\d{2}\.csv$")
    try:
        for fname in os.listdir(daily_dir):
            if fname == baseline_name:
                continue
            full = os.path.join(daily_dir, fname)
            if pattern.match(fname) and fname.endswith(".csv"):
                try:
                    os.remove(full)
                    print(f"🗑️ Deleted dated CSV: {full}")
                except Exception as e:
                    print(f"⚠️ Failed to delete {full}: {e}")
            elif fname.endswith(".csv"):
                try:
                    os.remove(full)
                    print(f"🗑️ Deleted stray CSV: {full}")
                except Exception as e:
                    print(f"⚠️ Failed to delete stray CSV {full}: {e}")
    except Exception as e:
        print(f"⚠️ Error while cleaning dated CSVs: {e}")

# meta id parsing/generation helpers
def parse_meta_id(meta_id):
    """
    Parse id like META-2025-000123 -> returns (year:int, seq:int) or (None,None)
    """
    if not meta_id:
        return None, None
    m = re.match(rf"^{META_ID_PREFIX}-(\d{{4}})-0*(\d+)$", str(meta_id))
    if not m:
        return None, None
    year = int(m.group(1))
    seq = int(m.group(2))
    return year, seq

def next_meta_id_for_year(existing_ids_set, year):
    max_seq = 0
    for mid in existing_ids_set:
        y, seq = parse_meta_id(mid)
        if y == year and seq is not None:
            if seq > max_seq:
                max_seq = seq
    next_seq = max_seq + 1
    return f"{META_ID_PREFIX}-{year}-{str(next_seq).zfill(6)}"

def extract_year_from_mod_time(mod_time_str):
    """
    Try to parse year from mod_time string like '2025-05-21 08:32:40 +0000'.
    Returns integer year if possible, otherwise None.
    """
    if not mod_time_str:
        return None
    s = str(mod_time_str).strip()
    # common pattern: starts with YYYY-
    m = re.match(r"^(\d{4})[-/]", s)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            pass
    # fallback: try to parse datetime
    for fmt in ("%Y-%m-%d %H:%M:%S %z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.year
        except Exception:
            continue
    # last resort: if string contains 4-digit year anywhere, pick first
    m2 = re.search(r"(\d{4})", s)
    if m2:
        try:
            return int(m2.group(1))
        except Exception:
            pass
    return None

# CVE extraction
CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)
def extract_cve(references_field):
    """
    Extract first CVE-like token from references (string like 'CVE-2007-4387;OSVDB-37667;...')
    Returns e.g. 'CVE-2007-4387' or None.
    """
    if not references_field:
        return None
    s = str(references_field)
    m = CVE_RE.search(s)
    return m.group(1).upper() if m else None

def scan_existing_ids_from_ddb(table):
    """Scan DynamoDB table and return set of existing 'id' PKs."""
    existing = set()
    client = table.meta.client
    paginator = client.get_paginator("scan")
    try:
        for page in paginator.paginate(TableName=table.name, ProjectionExpression="id"):
            for it in page.get("Items", []):
                if "id" in it:
                    existing.add(it["id"])
    except Exception:
        # ignore scan errors; return whatever collected
        pass
    return existing

# ---------- Main function ----------
def sync_today_with_dynamodb(current_csv_path, config=None):
    """
    Sync CSV -> DynamoDB with config overrides.
    - Generates unique META-{year}-{6digit} id for new rows using mod_time year.
    - Uses that generated id as DynamoDB partition key (stored in attribute 'id').
    - Stores original module key as 'module_id'.
    - Adds 'cve_id' extracted from 'references'.
    - Overwrites baseline CSV with merged results and removes dated CSVs.
    """
    cfg = _resolve_config(config)
    TABLE_NAME = cfg["TABLE_NAME"]
    DAILY_DIR = cfg["DAILY_DIR"]
    BASELINE_FILE = cfg["BASELINE_FILE"]
    BATCH_PROGRESS_INTERVAL = cfg["BATCH_PROGRESS_INTERVAL"]

    ensure_daily_dir(DAILY_DIR)
    ddb = connect_dynamodb(cfg)
    table = create_table_if_missing(ddb, TABLE_NAME)

    # load incoming CSV
    df_new = pd.read_csv(current_csv_path, dtype=str)
    new_count = len(df_new)
    print(f"ℹ️ Incoming transformed rows: {new_count}")

    # Validation
    if "id" not in df_new.columns:
        raise ValueError("Incoming CSV must contain an 'id' column (module key)")

    # map module_key -> row dict for incoming
    new_map = {}
    for _, r in df_new.iterrows():
        rid = r.get("id")
        if pd.isna(rid) or str(rid).strip() == "":
            continue
        new_map[str(rid).strip()] = r.to_dict()

    # load baseline (if exists) as module_key -> row dict
    base_map = {}
    baseline_exists = os.path.exists(BASELINE_FILE)
    if baseline_exists:
        df_base = pd.read_csv(BASELINE_FILE, dtype=str)
        for _, r in df_base.iterrows():
            mid = r.get("module_id") or r.get("moduleid") or r.get("id")
            # If baseline was using generated id in 'id', ensure module_id column exists; we try multiple fallbacks
            if pd.isna(mid) or str(mid).strip() == "":
                # if module_id missing, try to use 'id' column as module_id (legacy)
                mid = r.get("id")
            if pd.isna(mid) or str(mid).strip() == "":
                continue
            base_map[str(mid).strip()] = r.to_dict()
        print(f"ℹ️ Baseline found with {len(base_map)} rows")
    else:
        print("ℹ️ No baseline found (first run)")

    # compute changed module ids (new modules or modules with changed content)
    changed_module_keys = []
    for module_key, new_row in new_map.items():
        base_row = base_map.get(module_key)
        if base_row is None:
            changed_module_keys.append(module_key)
        else:
            if rows_differ(new_row, base_row):
                changed_module_keys.append(module_key)

    print(f"ℹ️ Total changed module keys to consider: {len(changed_module_keys)}")

    # collect existing generated ids (to avoid collisions)
    existing_generated_ids = scan_existing_ids_from_ddb(table)
    # also include generated ids that might exist in baseline (baseline rows may contain id field)
    for v in base_map.values():
        possible_id = v.get("id")
        if possible_id:
            existing_generated_ids.add(possible_id)

    # prepare to_write: for every changed module, generate a unique META id for it (if not already in baseline)
    to_write = []
    # compute per-year next id sequences by inspecting existing_generated_ids
    # we'll call next_meta_id_for_year(existing_generated_ids, year) when needed
    for module_key in changed_module_keys:
        csv_row = new_map.get(module_key) or base_map.get(module_key)
        if csv_row is None:
            continue

        # attach cve_id (extract from references)
        csv_row["cve_id"] = extract_cve(csv_row.get("references"))

        # decide year: prefer mod_time -> uploaded_date -> current year
        mod_time_val = csv_row.get("mod_time") or csv_row.get("mod_time".lower()) or csv_row.get("modtime")
        year = None
        if mod_time_val:
            year = extract_year_from_mod_time(mod_time_val)
        if year is None:
            uploaded_date = csv_row.get("uploaded_date")
            if uploaded_date:
                try:
                    year = int(str(uploaded_date)[:4])
                except Exception:
                    year = None
        if year is None:
            year = int(time.strftime("%Y"))

        # if baseline already contained a generated id for this module, reuse it
        baseline_entry = base_map.get(module_key, {})
        existing_id_for_module = baseline_entry.get("id")
        if existing_id_for_module and existing_id_for_module in existing_generated_ids:
            generated_id = existing_id_for_module
        else:
            # generate a new unique META id for this year
            generated_id = next_meta_id_for_year(existing_generated_ids, year)
            existing_generated_ids.add(generated_id)

        # prepare item for DynamoDB
        item = {}
        for k, v in csv_row.items():
            if pd.isna(v) or (isinstance(v, str) and v.strip() == ""):
                item[k] = None
            else:
                item[k] = v
        item["id"] = generated_id            # partition key in DynamoDB
        item["module_id"] = module_key       # original module key
        item["uploaded_date"] = item.get("uploaded_date") or time.strftime("%Y-%m-%d")
        # ensure cve_id is present (may be None)
        item["cve_id"] = item.get("cve_id")

        # compare with existing item in DDB to avoid unnecessary writes
        ddb_item = None
        try:
            resp = table.get_item(Key={"id": generated_id})
            ddb_item = resp.get("Item")
        except ClientError as e:
            print(f"⚠️ Warning fetching id={generated_id} from DDB: {e}")
            ddb_item = None

        if ddb_item is None:
            to_write.append(item)
        else:
            if rows_differ(item, ddb_item):
                to_write.append(item)
            else:
                # already up-to-date
                pass

    # batch write to DynamoDB
    uploaded_ids = []
    if to_write:
        print(f"⬆️ Writing {len(to_write)} item(s) to DynamoDB...")
        with table.batch_writer(overwrite_by_pkeys=["id"]) as batch:
            cnt = 0
            for item in to_write:
                # convert floats to Decimal, handle NaN/inf, remove empty strings
                safe_item = {}
                for k, v in item.items():
                    # convert float -> Decimal
                    if isinstance(v, float):
                        if math.isnan(v) or math.isinf(v):
                            safe_item[k] = None
                        else:
                            try:
                                safe_item[k] = Decimal(str(v))
                            except (InvalidOperation, Exception):
                                safe_item[k] = str(v)
                    else:
                        # convert "None-like" strings -> None
                        if isinstance(v, str) and v.strip() == "":
                            safe_item[k] = None
                        else:
                            safe_item[k] = v
                try:
                    batch.put_item(Item=safe_item)
                    uploaded_ids.append(safe_item["id"])
                except ClientError as e:
                    print(f"❌ Failed to put item id={safe_item.get('id')}: {e}")
                cnt += 1
                if cnt % BATCH_PROGRESS_INTERVAL == 0 or cnt == len(to_write):
                    print(f"⬆️ Batch wrote {cnt}/{len(to_write)}")
    else:
        print("ℹ️ Nothing to write to DynamoDB.")

    # Persist baseline: merge base_map and new_map but store generated id and module_id
    # Build merged_map keyed by module_key
    merged_map = base_map.copy()
    # For modules in new_map, update merged_map entries with latest CSV data
    for module_key, csv_row in new_map.items():
        merged_map[module_key] = csv_row.copy()

    # Ensure each merged_map row has 'id' (generated id) and 'module_id' and cve_id
    for module_key in merged_map.keys():
        # if baseline already had generated id, keep; else, if we wrote a new item for this module, find it
        baseline_entry = merged_map.get(module_key, {})
        # if baseline_entry already has 'id' (generated) keep it
        if baseline_entry.get("id"):
            pass
        else:
            # try to find in to_write list the item with module_id == module_key
            found = next((it for it in to_write if it.get("module_id") == module_key), None)
            if found:
                merged_map[module_key]["id"] = found.get("id")
        # ensure module_id present
        merged_map[module_key]["module_id"] = module_key
        # ensure cve_id present
        merged_map[module_key]["cve_id"] = merged_map[module_key].get("cve_id") or extract_cve(merged_map[module_key].get("references"))
        # ensure uploaded_date
        if not merged_map[module_key].get("uploaded_date"):
            merged_map[module_key]["uploaded_date"] = time.strftime("%Y-%m-%d")

    # Prepare baseline DataFrame and write (columns union)
    all_cols = set()
    for v in merged_map.values():
        all_cols.update(v.keys())
    # Make sure at least these columns exist
    all_cols.update(["id", "module_id", "cve_id", "uploaded_date"])
    baseline_rows = []
    for module_key, row in merged_map.items():
        r = row.copy()
        r["id"] = r.get("id")  # may be None for never-uploaded modules
        r["module_id"] = module_key
        r["cve_id"] = r.get("cve_id")
        r["uploaded_date"] = r.get("uploaded_date") or time.strftime("%Y-%m-%d")
        baseline_rows.append(r)

    df_baseline = pd.DataFrame(baseline_rows, columns=sorted(list(all_cols)))
    try:
        df_baseline.to_csv(BASELINE_FILE, index=False)
        print(f"✅ Baseline CSV updated: {BASELINE_FILE}")
    except Exception as e:
        print(f"⚠️ Failed to update baseline CSV: {e}")

    # cleanup other dated CSV files
    remove_dated_csvs_keep_baseline(DAILY_DIR, BASELINE_FILE)

    result = {
        "timestamp": time.strftime("%Y-%m-%d_%H%M%S"),
        "total_incoming": new_count,
        "changed_considered": len(changed_module_keys),
        "to_write": len(to_write),
        "uploaded": len(uploaded_ids),
        "baseline_file": BASELINE_FILE
    }
    print("ℹ️ Sync result:", result)
    return result
