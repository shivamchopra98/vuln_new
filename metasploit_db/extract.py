# extract_metasploit.py
import os
import requests
from datetime import datetime

def download_raw_json(url, output_dir):
    """
    Download the metasploit JSON and save to output_dir/metasploit.json (dated name optional).
    Returns saved file path.
    """
    os.makedirs(output_dir, exist_ok=True)
    # we will save as metasploit.json (not dated) to avoid extra dated files
    filename = "metasploit.json"
    save_path = os.path.join(output_dir, filename)

    print(f"⬇️ Downloading JSON from {url} → {save_path}")
    resp = requests.get(url, stream=True, timeout=60)
    resp.raise_for_status()
    with open(save_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
    print("✅ Download complete")
    return save_path
