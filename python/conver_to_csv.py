import json
import pandas as pd
import os

# ✅ ตำแหน่งโฟลเดอร์ไฟล์ .py นี้
current_dir = os.path.dirname(os.path.abspath(__file__))

# ✅ Path ไปยัง database/ และ Feature_ML/
base_dir = os.path.join(current_dir, "..", "database")
output_dir = os.path.join(current_dir, "..", "Feature_ML")

# ✅ JSON input
phishing_json_path = os.path.join(base_dir, "phishing_urls.json")
legitimate_json_path = os.path.join(base_dir, "legitimate_urls.json")

# ✅ CSV output
phishing_csv_path = os.path.join(output_dir, "phishing_urls.csv")
legitimate_csv_path = os.path.join(output_dir, "legitimate_urls.csv")

def convert_json_to_csv(json_path, csv_path):
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        df = pd.json_normalize(data)
        df.to_csv(csv_path, index=False, encoding="utf-8")
        print(f"✅ Saved CSV: {csv_path} ({len(df)} rows)")
    except FileNotFoundError:
        print(f"❌ File not found: {json_path}")
    except Exception as e:
        print(f"❌ Error processing {json_path}: {e}")

# ✅ แปลงทั้งสองไฟล์
convert_json_to_csv(phishing_json_path, phishing_csv_path)
convert_json_to_csv(legitimate_json_path, legitimate_csv_path)
