import random
import os

# ชี้ไฟล์ที่อยู่ข้างนอกโฟลเดอร์ python
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
input_path = os.path.join(base_dir, "phishing_urls2.txt")
output_path = os.path.join(base_dir, "phishing_shuffle_urls.txt")

with open(input_path, "r", encoding="utf-8") as f:
    lines = f.readlines()

random.shuffle(lines)

with open(output_path, "w", encoding="utf-8") as f:
    f.writelines(lines)

print(f"✅ สลับบรรทัดเสร็จแล้ว → {output_path}")
