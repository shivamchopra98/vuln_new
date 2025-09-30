# transform_metasploit.py
import json
import re
import os
from datetime import datetime
import pandas as pd
import csv

CLEAN_WHITESPACE_RE = re.compile(r"\s+")

def to_semicolon(value):
    """Convert lists to semicolon-joined strings, flatten newlines to spaces, clean whitespace."""
    if value is None:
        return None
    if isinstance(value, list):
        parts = []
        for x in value:
            s = str(x)
            s = s.replace("\r", " ").replace("\n", " ")
            s = CLEAN_WHITESPACE_RE.sub(" ", s).strip()
            if s:
                parts.append(s)
        return ";".join(parts) if parts else None
    s = str(value)
    s = s.replace("\r", " ").replace("\n", " ")
    s = CLEAN_WHITESPACE_RE.sub(" ", s).strip()
    return s if s != "" else None

def clean_text(value):
    """Replace newlines, collapse whitespace, trim."""
    if value is None:
        return None
    s = str(value)
    s = s.replace("\r", " ").replace("\n", " ")
    s = CLEAN_WHITESPACE_RE.sub(" ", s).strip()
    return s if s != "" else None

def transform_json(json_path):
    """
    Read metasploit modules metadata JSON and write a clean CSV with only these columns:
    id,name,fullname,aliases,rank,type,author,description,references,platform,autofilter_services,rport,path,ref_name,uploaded_date
    Returns path to generated CSV.
    """
    print(f"🔄 Transforming JSON: {json_path}")
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    rows = []
    for module_key, meta in data.items():
        # Select and clean fields
        row = {
            "id": module_key,
            "name": clean_text(meta.get("name") or ""),
            "fullname": clean_text(meta.get("fullname") or module_key),
            "aliases": to_semicolon(meta.get("aliases")),
            "rank": meta.get("rank"),
            "type": clean_text(meta.get("type")),
            "author": to_semicolon(meta.get("author")),
            "description": clean_text(meta.get("description")),
            "references": to_semicolon(meta.get("references")),
            "platform": to_semicolon(meta.get("platform")),
            "autofilter_services": to_semicolon(meta.get("autofilter_services")),
            "rport": meta.get("rport"),
            "path": clean_text(meta.get("path")),
            "ref_name": clean_text(meta.get("ref_name") or module_key),
        }
        rows.append(row)

    df = pd.DataFrame(rows, columns=[
        "id","name","fullname","aliases","rank","type","author","description",
        "references","platform","autofilter_services","rport","path","ref_name"
    ])

    # Add uploaded_date as today's date
    today_str = datetime.now().strftime("%Y-%m-%d")
    df["uploaded_date"] = today_str

    csv_path = os.path.splitext(json_path)[0] + ".csv"
    # Write CSV ensuring single-line rows
    df.to_csv(
        csv_path,
        index=False,
        lineterminator="\n",
        quoting=csv.QUOTE_MINIMAL,
        escapechar="\\",
        encoding="utf-8"
    )

    print(f"✅ CSV written: {csv_path} (rows={len(df)}) — all rows are single-line cleaned entries")
    return csv_path
