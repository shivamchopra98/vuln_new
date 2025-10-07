# extract_metasploit.py
import requests

def download_raw_json_to_text(url: str, timeout: int = 60) -> str:
    """
    Download remote JSON and return decoded text (no local file).
    """
    print(f"⬇️ Downloading JSON from {url}")
    resp = requests.get(url, stream=True, timeout=timeout)
    resp.raise_for_status()
    resp.encoding = resp.encoding or "utf-8"
    text = resp.text
    print(f"✅ Download complete (size={len(text)} bytes)")
    return text
