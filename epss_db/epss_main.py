# epss_main.py
from extract import extract_epss
from transform import transform_epss
from load import load

if __name__ == "__main__":
    print("🚀 Starting ETL pipeline...")

    # Step 1: Extract
    extracted_data = extract_epss()  # capture returned data

    # Step 2: Transform
    transformed_data = transform_epss(extracted_data)  # pass extracted data

    # Step 3: Load to DynamoDB
    load(transformed_data)
