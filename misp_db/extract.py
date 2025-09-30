# extract.py
import os
import requests

BASE_DIR = os.path.dirname(__file__)
DAILY_DIR = os.path.join(BASE_DIR, "daily_extract")
os.makedirs(DAILY_DIR, exist_ok=True)

MISP_JSON_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
TEMP_JSON_FILE = os.path.join(DAILY_DIR, "threat_actor.json")

def extract_misp():
    """
    Download the MISP threat-actor JSON and return the path to the saved file.
    """
    print(f"⬇️ Downloading MISP JSON from {MISP_JSON_URL} → {TEMP_JSON_FILE}")
    resp = requests.get(MISP_JSON_URL, timeout=60)
    resp.raise_for_status()
    with open(TEMP_JSON_FILE, "w", encoding="utf-8") as fh:
        fh.write(resp.text)
    print("✅ Download complete")
    return TEMP_JSON_FILE

if __name__ == "__main__":
    extract_misp()
