import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix
import numpy as np
import os

# ===== 1. โหลด result_log.json =====
base_dir = os.path.dirname(os.path.abspath(__file__))
json_path = os.path.join(base_dir, '../database/result_log.json')

with open(json_path, 'r', encoding='utf-8') as f:
    result_data = json.load(f)

df_result = pd.DataFrame(result_data)
df_result['url_normalized'] = df_result['url'].str.lower().str.strip()

# ===== 2. โหลด CSV ที่มี label จริง =====
csv_path = os.path.join(base_dir, '../database/Random_URL_Samples.csv')
df_true_raw = pd.read_csv(csv_path)

# รวม Legitimate และ Phishing URLs เป็น DataFrame เดียว
legit_df = pd.DataFrame({
    'url': df_true_raw['Legitimate URLs'].dropna().str.lower().str.strip(),
    'true_label': 'safe'
})
phish_df = pd.DataFrame({
    'url': df_true_raw['Phishing URLs'].dropna().str.lower().str.strip(),
    'true_label': 'unsafe'
})
df_true = pd.concat([legit_df, phish_df], ignore_index=True)
df_true['url_normalized'] = df_true['url']

# ===== 3. รวมข้อมูลจาก CSV และ JSON =====
df_merged = pd.merge(df_true, df_result, on='url_normalized', how='inner')

# ===== ตรวจสอบความครบถ้วน =====
print(f"จำนวนข้อมูลหลัง merge: {len(df_merged)} รายการ")  # ต้องได้ 200
print(df_merged['true_label'].value_counts())  # ควรเป็น 100 / 100

# ถ้า merge ไม่ครบ ให้ดูว่า URL ไหนไม่ตรง
if len(df_merged) != 200:
    merged_urls = set(df_merged['url_normalized'])
    missing_in_csv = set(df_true['url_normalized']) - merged_urls
    missing_in_json = set(df_result['url_normalized']) - merged_urls

    print(f"URL ที่หายจาก JSON: {len(missing_in_csv)}")
    print(f"URL ที่หายจาก CSV: {len(missing_in_json)}")

# ===== 4. ประเมินผลประสิทธิภาพ =====
true_labels = df_merged['true_label']
predicted_labels = df_merged['result']

report = classification_report(true_labels, predicted_labels, output_dict=True)
report_df = pd.DataFrame(report).transpose()
print("\n=== Classification Report ===")
print(report_df.round(2))

# ===== 5. แสดงผลลัพธ์เป็นตาราง =====
fig, ax = plt.subplots(figsize=(8, 6))
ax.axis('off')
tbl = ax.table(cellText=report_df.round(2).values,
               colLabels=report_df.columns,
               rowLabels=report_df.index,
               cellLoc='center', loc='center')
tbl.scale(1, 1.5)
plt.title("ผลประเมินประสิทธิภาพที่ได้จากโมเดล", fontsize=14)
plt.show()

# ===== 6. Confusion Matrix =====
cm = confusion_matrix(true_labels, predicted_labels, labels=['safe', 'unsafe'])
plt.figure(figsize=(6, 5))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['safe', 'unsafe'], yticklabels=['safe', 'unsafe'])
plt.xlabel('Predicted')
plt.ylabel('True')
plt.title('Confusion Matrix')
plt.show()
