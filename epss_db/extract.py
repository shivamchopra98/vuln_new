import csv
import requests
import time
import os
import sys

DATA_DIR = r"C:\Users\ShivamChopra\Projects\vuln\epss_db"
ALL_CVE_CSV = os.path.join(DATA_DIR, "daily_extract", "all_cves.csv")
EPSs_CSV = os.path.join(DATA_DIR, "epss_extract.csv")
API_URL = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100
SLEEP_TIME = 0.06  # ~1000 requests/minute

# Increase CSV field size limit
max_int = sys.maxsize
while True:
    try:
        csv.field_size_limit(max_int)
        break
    except OverflowError:
        max_int = int(max_int / 10)

def extract_epss():
    # -----------------------------
    # Step 1: Read all CVEs
    # -----------------------------
    all_cves = []
    with open(ALL_CVE_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_id = row.get("id", "").strip()
            if cve_id:
                all_cves.append(cve_id)

    print(f"📄 Total CVEs in input: {len(all_cves)}")

    # -----------------------------
    # Step 2: Read already processed CVEs
    # -----------------------------
    processed_cves = set()
    if os.path.exists(EPSs_CSV):
        with open(EPSs_CSV, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve = row.get("cve", "").strip()
                if cve:
                    processed_cves.add(cve)

    print(f"📂 Already processed: {len(processed_cves)} CVEs")

    # -----------------------------
    # Step 3: Remaining CVEs
    # -----------------------------
    remaining_cves = [cve for cve in all_cves if cve not in processed_cves]
    print(f"🟡 Remaining CVEs: {len(remaining_cves)}")
    if not remaining_cves:
        return []

    # -----------------------------
    # Step 4: Fetch EPSs data in batches
    # -----------------------------
    results = []
    if not os.path.exists(EPSs_CSV):
        with open(EPSs_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["cve", "epss", "percentile", "date"])

    for i in range(0, len(remaining_cves), BATCH_SIZE):
        batch = remaining_cves[i:i+BATCH_SIZE]
        batch_str = ",".join(batch)
        url = f"{API_URL}?cve={batch_str}&pretty=true"

        try:
            resp = requests.get(url)
            if resp.status_code == 429:
                print("⚠️ Rate limit exceeded. Sleeping for 120 seconds...")
                time.sleep(120)
                continue
            elif resp.status_code != 200:
                print(f"❌ Error {resp.status_code} for batch {i//BATCH_SIZE + 1}")
                time.sleep(SLEEP_TIME)
                continue

            data = resp.json().get("data", [])
            new_count = 0
            with open(EPSs_CSV, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                for item in data:
                    cve = item["cve"]
                    if cve not in processed_cves:
                        writer.writerow([cve, item.get("epss"), item.get("percentile"), item.get("date")])
                        results.append(item)
                        processed_cves.add(cve)
                        new_count += 1

            print(f"✅ Batch {i//BATCH_SIZE + 1}: {new_count} CVEs processed. Total so far: {len(processed_cves)}")
            time.sleep(SLEEP_TIME)

        except Exception as e:
            print(f"❌ Exception during batch {i//BATCH_SIZE + 1}: {e}")
            time.sleep(SLEEP_TIME)

    print(f"✅ Extraction complete. Total new CVEs fetched: {len(results)}")
    return results
