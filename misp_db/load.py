# load.py
import os
import json
import math
import time
import boto3
import pandas as pd
from decimal import Decimal
from botocore.exceptions import ClientError

DEFAULT_CONFIG = {
    "TABLE_NAME": "misp_data",
    "DDB_ENDPOINT": "http://localhost:8000",
    "AWS_REGION": "us-east-1",
    "BATCH_PROGRESS_INTERVAL": 100
}

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
            KeySchema=[{"AttributeName": "uuid", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "uuid", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        table.meta.client.get_waiter("table_exists").wait(TableName=table_name)
        print("✅ Table created.")
    return ddb_resource.Table(table_name)

def _normalize_for_compare(value):
    """Normalize a value to be comparable and DynamoDB-safe."""
    import pandas as pd

    if value is None:
        return None
    if isinstance(value, (list, dict, tuple)):
        try:
            return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        except Exception:
            return str(value)
    try:
        if pd.isna(value):
            return None
    except Exception:
        pass
    if isinstance(value, (int, float, Decimal)):
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            return None
        return str(value)
    s = str(value).strip()
    if s.lower() in {"nan", "none", ""}:
        return None
    return s

def _scan_table_to_map(table):
    """Scan DynamoDB table and return uuid -> item dict."""
    client = table.meta.client
    paginator = client.get_paginator("scan")
    existing = {}
    for page in paginator.paginate(TableName=table.name):
        for it in page.get("Items", []):
            uuid = it.get("uuid") or it.get("UUID") or it.get("id")
            if uuid:
                existing[str(uuid)] = it
    return existing

def rows_differ(csv_row: dict, ddb_item: dict) -> bool:
    """Return True if normalized rows differ."""
    norm_csv = {k: _normalize_for_compare(v) for k, v in csv_row.items()}
    norm_ddb = {k: _normalize_for_compare(v) for k, v in (ddb_item or {}).items()}
    return norm_csv != norm_ddb

def load_misp_incremental(df: pd.DataFrame, config: dict = None):
    """Load transformed DataFrame into DynamoDB incrementally."""
    if df is None or df.empty:
        print("ℹ️ Nothing to load (empty dataframe).")
        return {"inserted": 0, "updated": 0, "skipped": 0}

    cfg = DEFAULT_CONFIG.copy()
    if config:
        cfg.update(config)

    ddb = connect_dynamodb(cfg)
    table = create_table_if_missing(ddb, cfg["TABLE_NAME"])

    # Prepare rows
    rows = []
    for _, r in df.iterrows():
        rowd = {k: _normalize_for_compare(v) for k, v in r.items()}
        if "uuid" not in rowd or rowd["uuid"] is None:
            continue
        rowd["uuid"] = str(rowd["uuid"])
        rows.append(rowd)

    total_rows = len(rows)
    print(f"ℹ️ Prepared {total_rows} rows for comparison/upload")

    existing_map = _scan_table_to_map(table)
    print(f"ℹ️ DynamoDB currently has {len(existing_map)} items")

    to_write = []
    skipped = 0
    inserted = 0
    updated = 0

    for i, row in enumerate(rows, start=1):
        uuid = row["uuid"]
        existing = existing_map.get(uuid)
        if existing is None:
            to_write.append(row)
            inserted += 1
        else:
            if rows_differ(row, existing):
                to_write.append(row)
                updated += 1
            else:
                skipped += 1

        if i % max(1, cfg["BATCH_PROGRESS_INTERVAL"]) == 0:
            print(f"ℹ️ Compared {i}/{total_rows} rows (to_write={len(to_write)}, skipped={skipped})")

    print(f"ℹ️ Totals -> new: {inserted}, updated: {updated}, skipped(same): {skipped}")

    written = 0
    if to_write:
        print(f"⬆️ Writing {len(to_write)} items to DynamoDB (batch_writer)...")
        with table.batch_writer() as batch:
            for i, it in enumerate(to_write, start=1):
                safe_item = {}
                for k, v in it.items():
                    if isinstance(v, (list, dict)):
                        try:
                            safe_item[k] = json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                        except Exception:
                            safe_item[k] = str(v)
                    else:
                        safe_item[k] = v
                safe_item["uuid"] = str(safe_item["uuid"])
                try:
                    batch.put_item(Item=safe_item)
                    written += 1
                except ClientError as e:
                    print(f"❌ Failed to put item uuid={safe_item.get('uuid')}: {e}")
                if i % cfg["BATCH_PROGRESS_INTERVAL"] == 0 or i == len(to_write):
                    print(f"⬆️ Batch wrote {i}/{len(to_write)} items")
    else:
        print("ℹ️ Nothing to write to DynamoDB.")

    summary = {
        "total_rows": total_rows,
        "new": inserted,
        "updated": updated,
        "skipped": skipped,
        "written": written,
    }
    print("✅ Load summary:", summary)
    return summary
