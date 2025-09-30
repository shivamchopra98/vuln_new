# transform.py
import os
import json
import pandas as pd
from typing import Any, Dict, List

BASE_DIR = os.path.dirname(__file__)

def _ensure_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    if isinstance(x, dict):
        # If dict appears where a list is expected, return the dict's values.
        return list(x.values())
    return [x]

def _flatten_cluster(cluster: Dict[str, Any]) -> Dict[str, Any]:
    """
    Flatten a single cluster object into a flat dict.
    Keep main top-level fields and expand meta.* keys.
    """
    out: Dict[str, Any] = {}

    # Common top-level fields (safe-get)
    out["description"] = cluster.get("description")
    out["related"] = cluster.get("related")
    out["uuid"] = cluster.get("uuid") or cluster.get("id") or cluster.get("value")
    out["value"] = cluster.get("value") or cluster.get("name") or cluster.get("title")

    # refs/tags
    if "refs" in cluster:
        out["meta.refs"] = cluster.get("refs")
    if "tags" in cluster:
        out["tags"] = cluster.get("tags")
    if "synonyms" in cluster:
        out["meta.synonyms"] = cluster.get("synonyms")

    # Flatten meta.*
    meta = cluster.get("meta") or {}
    if isinstance(meta, dict):
        for mk, mv in meta.items():
            out[f"meta.{mk}"] = mv

    # Copy a few other standard fields if present
    for k in ("type", "name", "category", "namespace"):
        if k in cluster and cluster.get(k) is not None:
            out[k] = cluster.get(k)

    return out

def transform_misp(json_file_path: str) -> pd.DataFrame:
    """
    Read the downloaded MISP JSON and return a flattened DataFrame.
    The DataFrame contains a 'uuid' column (used as partition key).
    """
    if not os.path.exists(json_file_path):
        raise FileNotFoundError(json_file_path)

    with open(json_file_path, "r", encoding="utf-8") as fh:
        parsed = json.load(fh)

    # Diagnostic print
    if isinstance(parsed, dict):
        top_keys = list(parsed.keys())
        print(f"ℹ️ JSON top-level keys: {top_keys}")
    else:
        print(f"ℹ️ JSON top-level type: {type(parsed).__name__}")

    # Try multiple known shapes to locate cluster entries
    clusters: List[Dict] = []

    if isinstance(parsed, dict) and "clusters" in parsed:
        print("ℹ️ Found clusters in top-level 'clusters'")
        clusters = _ensure_list(parsed.get("clusters"))

    if not clusters and isinstance(parsed, dict) and "value" in parsed:
        print("ℹ️ Found clusters in top-level 'value'")
        clusters = _ensure_list(parsed.get("value"))

    if not clusters and isinstance(parsed, list):
        print("ℹ️ JSON is a top-level list; using that as clusters")
        clusters = _ensure_list(parsed)

    if not clusters and isinstance(parsed, dict):
        # if parsed is a dict mapping uuid->cluster objects
        sample_vals = list(parsed.values())[:6]
        if sample_vals and all(isinstance(v, dict) for v in sample_vals):
            if any(("uuid" in v or "value" in v or "name" in v) for v in sample_vals):
                print("ℹ️ JSON appears to be a dict mapping -> cluster objects; using values()")
                clusters = _ensure_list(parsed)

    # fallback: try "data" key or first list-of-dicts value
    if not clusters and isinstance(parsed, dict) and "data" in parsed:
        print("ℹ️ Found 'data' key; attempting to use it")
        clusters = _ensure_list(parsed.get("data"))

    if not clusters and isinstance(parsed, dict):
        for v in parsed.values():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                print("ℹ️ Fallback: using first list-of-dicts found in top-level values")
                clusters = _ensure_list(v)
                break

    if not clusters:
        print("⚠️ No clusters found in JSON")
        return pd.DataFrame()  # empty

    rows = []
    for c in clusters:
        if not isinstance(c, dict):
            continue
        flat = _flatten_cluster(c)
        # ensure uuid exists; fallback to value if missing
        if not flat.get("uuid"):
            flat["uuid"] = c.get("uuid") or c.get("id") or c.get("value")
        rows.append(flat)

    if not rows:
        print("⚠️ No usable rows after flattening")
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    # rearrange columns: description, related, uuid, value, then meta.* sorted, then others
    cols = []
    for c in ("description", "related", "uuid", "value"):
        if c in df.columns:
            cols.append(c)
    meta_cols = sorted([c for c in df.columns if c.startswith("meta.")])
    other_cols = [c for c in df.columns if c not in cols + meta_cols]
    final_cols = cols + meta_cols + other_cols
    # ensure DataFrame has these columns in the order
    df = df[final_cols]
    print(f"ℹ️ Transformed {len(df)} entries from MISP JSON (columns: {len(df.columns)})")
    return df

if __name__ == "__main__":
    # quick smoke test when run directly (not required)
    print("Run transform_misp(json_path) from misp_main.py")
