# misp_main.py
import os
from extract import extract_misp
from transform import transform_misp
from load import load_misp_incremental

BASE_DIR = os.path.dirname(__file__)
DAILY_DIR = os.path.join(BASE_DIR, "daily_extract")

def main():
    print("🚀 Starting MISP ETL pipeline...")

    # 1) extract
    json_path = extract_misp()

    # 2) transform
    df = transform_misp(json_path)

    # 3) load (incremental compare + write)
    result = load_misp_incremental(df)

    # 4) cleanup - remove the downloaded JSON
    try:
        os.remove(json_path)
        print(f"🗑️ Removed temporary JSON: {json_path}")
    except Exception as e:
        print(f"⚠️ Failed to remove temporary JSON: {e}")

    print("✅ ETL pipeline finished. Summary:", result)

if __name__ == "__main__":
    main()
