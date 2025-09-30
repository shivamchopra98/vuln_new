import os
import requests
from datetime import datetime

def download_raw_json(url: str, output_dir: str) -> str:
    """
    Download JSON feed and save to output_dir/YYYY-MM-DD.json.
    Returns saved path.
    """
    os.makedirs(output_dir, exist_ok=True)
    today = datetime.now().strftime("%Y-%m-%d")
    filename = f"{today}.json"
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
