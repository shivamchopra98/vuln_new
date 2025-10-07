# transform_metasploit.py
import json
import re
from datetime import datetime
from typing import Tuple, List, Dict

CLEAN_RE = re.compile(r"\s+")

def _clean_text(x):
    if x is None:
        return None
    s = str(x)
    s = s.replace("\r", " ").replace("\n", " ")
    s = CLEAN_RE.sub(" ", s).strip()
    return s if s != "" else None

def _to_semicolon(value):
    if value is None:
        return None
    if isinstance(value, list):
        parts = []
        for v in value:
            s = _clean_text(v)
            if s:
                parts.append(s)
        return ";".join(parts) if parts else None
    return _clean_text(value)

def transform_json_text_to_records_and_json_bytes(json_text: str) -> Tuple[List[Dict], bytes]:
    """
    Accept raw metasploit JSON text and return:
      - list of normalized dict records
      - bytes of the canonical transformed JSON (utf-8)
    """
    print("🔄 Transforming JSON (in memory)...")
    raw = json.loads(json_text)

    records = []
    for module_key, meta in raw.items():
        rec = {
            "module_key": module_key,
            "id": None,  # placeholder for generated META-id (filled in loader)
            "module_name": _clean_text(meta.get("name") or ""),
            "fullname": _clean_text(meta.get("fullname") or module_key),
            "aliases": _to_semicolon(meta.get("aliases")),
            "rank": _clean_text(meta.get("rank")),
            "type": _clean_text(meta.get("type")),
            "author": _to_semicolon(meta.get("author")),
            "description": _clean_text(meta.get("description")),
            "references": _to_semicolon(meta.get("references")),
            "platform": _to_semicolon(meta.get("platform")),
            "autofilter_services": _to_semicolon(meta.get("autofilter_services")),
            "rport": _clean_text(meta.get("rport")),
            "path": _clean_text(meta.get("path")),
            "ref_name": _clean_text(meta.get("ref_name") or module_key),
            "uploaded_date": datetime.utcnow().strftime("%Y-%m-%d")
        }
        records.append(rec)

    json_bytes = json.dumps(records, ensure_ascii=False, indent=2).encode("utf-8")
    print(f"✅ Transformation complete: records={len(records)} (json size={len(json_bytes)} bytes)")
    return records, json_bytes
