# transform_cisa.py
import json
import os
import re
from datetime import datetime

# Fields required in output (exact names requested)
OUTPUT_FIELDS = [
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "shortDescription",
    "requiredAction",
    "dueDate",
    "knownRansomwareCampaignUse",
    "notes",
    "cwes"
]

CLEAN_WS = re.compile(r"\s+")

def _clean_text(x):
    if x is None:
        return None
    s = str(x)
    s = s.replace("\r", " ").replace("\n", " ")
    s = CLEAN_WS.sub(" ", s).strip()
    return s if s != "" else None

def _extract_entries_from_cisa_raw(raw_obj):
    """
    Accepts the downloaded JSON object and returns a list of normalized dicts
    with keys from OUTPUT_FIELDS. The CISA feed structure may vary; handle common cases:
      - top-level key 'vulnerabilities' -> list
      - top-level 'knownExploitedVulnerabilities' -> list
      - or top-level is already a list
    Each entry is normalized.
    """
    entries = None
    # heuristics to find list
    if isinstance(raw_obj, dict):
        for candidate in ("vulnerabilities", "knownExploitedVulnerabilities", "knownExploitedVulnerabilitiesList", "items"):
            if candidate in raw_obj and isinstance(raw_obj[candidate], list):
                entries = raw_obj[candidate]
                break
        # old format: sometimes key "vulnerabilities" nested inside "data" or similar
        if entries is None:
            # try to find the first list value that looks like entries (list of dicts with "cveID" or "cve")
            for v in raw_obj.values():
                if isinstance(v, list) and v and isinstance(v[0], dict) and ("cveID" in v[0] or "cve" in v[0] or "vulnerabilityID" in v[0] or "cveID" in v[0]):
                    entries = v
                    break
    elif isinstance(raw_obj, list):
        entries = raw_obj

    if entries is None:
        # fallback: if top-level dict has items that look like records (dict with cveID)
        # try to collect values that are dicts with cve-like keys
        cand = []
        if isinstance(raw_obj, dict):
            for v in raw_obj.values():
                if isinstance(v, dict) and any(k.lower().startswith("cve") for k in v.keys()):
                    cand.append(v)
            if cand:
                return cand
        return []

    # Now normalize each entry to the OUTPUT_FIELDS
    normalized = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        # common field names used by CISA feed:
        # cveID or cveID (sometimes 'cveID' exact), vendorProject, product, vulnerabilityName, dateAdded,
        # shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, notes, cwes
        # Use flexible lookups
        def getf(*keys):
            for k in keys:
                if k in e:
                    return e[k]
                # case-insensitive fallback
                for ek in e.keys():
                    if ek.lower() == k.lower():
                        return e[ek]
            return None

        rec = {
            "cveID": _clean_text(getf("cveID", "cve", "vulnerabilityID", "cveId")),
            "vendorProject": _clean_text(getf("vendorProject", "vendor", "vendor_project", "vendorName")),
            "product": _clean_text(getf("product", "productName", "products")),
            "vulnerabilityName": _clean_text(getf("vulnerabilityName", "vulnerability_name", "vulnName", "vulnerabilityName")),
            "dateAdded": _clean_text(getf("dateAdded", "date_added", "datePublished", "dateAdded")),
            "shortDescription": _clean_text(getf("shortDescription", "short_description", "shortDescription")),
            "requiredAction": _clean_text(getf("requiredAction", "required_action", "requiredAction")),
            "dueDate": _clean_text(getf("dueDate", "due_date", "dueDate")),
            "knownRansomwareCampaignUse": _clean_text(getf("knownRansomwareCampaignUse", "knownRansomwareCampaignUse")),
            "notes": _clean_text(getf("notes", "note", "reference")),
            "cwes": _clean_text(getf("cwes", "cwe"))
        }

        # Ensure we have a cveID — if missing, skip record (can't be keyed)
        if not rec["cveID"]:
            # sometimes feed uses 'cveID' as list inside 'cveID' object; try other strategies
            # try scanning full entry for a CVE-like string
            import re
            CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", flags=re.IGNORECASE)
            found = None
            for v in e.values():
                try:
                    s = json.dumps(v)
                except Exception:
                    s = str(v)
                m = CVE_RE.search(s)
                if m:
                    found = m.group(0).upper()
                    break
            if found:
                rec["cveID"] = found
            else:
                # cannot identify a cveID — skip
                continue

        normalized.append(rec)
    return normalized

def transform_json(raw_json_path: str) -> str:
    """
    Read raw CISA JSON download at raw_json_path, extract required fields and
    write transformed JSON list back to same folder with same date-based name.
    Returns path to the transformed JSON (same file path).
    """
    print(f"🔄 Transforming CISA JSON: {raw_json_path}")
    with open(raw_json_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    entries = _extract_entries_from_cisa_raw(raw)
    # Add uploaded_date field as today's date for each record (ISO)
    today = datetime.now().strftime("%Y-%m-%d")
    for r in entries:
        r.setdefault("uploaded_date", today)

    # Overwrite the same path with normalized list
    with open(raw_json_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)
    print(f"✅ Transformed JSON written: {raw_json_path} (records={len(entries)})")
    return raw_json_path
