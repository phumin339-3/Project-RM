# train_model.py
import os, json, joblib
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")  # ใช้ backend ที่ไม่ต้องพึ่ง GUI
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report, accuracy_score, confusion_matrix,
    precision_recall_curve, roc_auc_score, average_precision_score,
    roc_curve, f1_score, precision_score, recall_score
)
from sklearn.inspection import permutation_importance

# ================== CONFIG ==================
TARGET_RECALL = 0.90                          # เป้าหมาย recall ของ class=unsafe (label=1)
THRESH_GRID   = np.linspace(0.0, 1.0, 201)    # สแกน threshold 0..1 step=0.005

# ================== Paths ==================
base_dir   = os.path.abspath(os.path.join(os.path.dirname(__file__), "../Feature_ML"))
phish_path = os.path.join(base_dir, "phishing_urls.csv")
legit_path = os.path.join(base_dir, "legitimate_urls.csv")

plot_dir = os.path.abspath(os.path.join(os.getcwd(), "python/plots"))
os.makedirs(plot_dir, exist_ok=True)

# ================== Load ==================
phish_df = pd.read_csv(phish_path)
legit_df = pd.read_csv(legit_path)

# ถ้าไม่มีคอลัมน์ label ให้ติดป้ายอัตโนมัติ (1=unsafe, 0=safe)
if "label" not in phish_df.columns:
    phish_df["label"] = 1
if "label" not in legit_df.columns:
    legit_df["label"] = 0

df_raw = pd.concat([phish_df, legit_df], ignore_index=True)

# ================== Base Features (ต้องสอดคล้องกับ app.py/url_checker.py) ==================
base_features = [
    # URL-level
    "length_url","length_hostname","ip","punycode","ratio_digits_url","ratio_digits_host",
    "nb_subdomains","tld_in_path","tld_in_subdomain","random_domain","shortening_service",
    "prefix_suffix","phish_hints","url_entropy","uses_https","is_http","num_query_params",
    "has_at_symbol","path_extension","tld_risk",
    # TLS/WHOIS/HTTP
    "ssl_valid","cert_days_left","san_count","cert_cn_matches_domain","domain_age_days",
    "days_since_update","has_whois_privacy","redirect_chain_len","final_domain_differs",
    "has_security_headers",
    # Typosquat (light)
    "typosquat_candidate",
    # Similarity scores (อาจไม่มีใน dataset → เติม 0 ให้)
    "typosquat_score_max","typosquat_score_mean","typosquat_distance",
    # Target
    "label"
]

# เติมคอลัมน์ที่ขาดหายให้ครบ โดยกำหนดค่า default ที่เหมาะสม
defaults = {
    # URL-level
    "length_url":0,"length_hostname":0,"ip":0,"punycode":0,"ratio_digits_url":0.0,"ratio_digits_host":0.0,
    "nb_subdomains":0,"tld_in_path":0,"tld_in_subdomain":0,"random_domain":0,"shortening_service":0,
    "prefix_suffix":0,"phish_hints":0,"url_entropy":0.0,"uses_https":0,"is_http":0,"num_query_params":0,
    "has_at_symbol":0,"path_extension":0,"tld_risk":0,
    # TLS/WHOIS/HTTP
    "ssl_valid":0,"cert_days_left":0,"san_count":0,"cert_cn_matches_domain":0,"domain_age_days":-1,
    "days_since_update":0,"has_whois_privacy":0,"redirect_chain_len":0,"final_domain_differs":0,
    "has_security_headers":0,
    # Typosquat
    "typosquat_candidate":0,
    # Similarity
    "typosquat_score_max":0,"typosquat_score_mean":0,"typosquat_distance":0,
}

for col in base_features:
    if col == "label":
        continue
    if col not in df_raw.columns:
        df_raw[col] = defaults.get(col, 0)

# สุดท้ายเลือกเฉพาะคอลัมน์ตามลำดับ base_features
df = df_raw[[c for c in base_features if c in df_raw.columns]].copy()

# ================== Extra Feature Engineering (ต้อง “ชื่อเดียวกัน” กับ app.py) ==================
# app.py คำนวณ 5 ฟีเจอร์นี้ตอนเสิร์ฟ → ที่เทรนต้องมีชื่อเดียวกัน และถูกบันทึกใน feature_order.json
df["url_length_ratio"] = df["length_url"] / (df["length_hostname"] + 1)
df["digit_ratio_diff"] = (df["ratio_digits_url"] - df["ratio_digits_host"]).abs()
df["domain_age_lt_90d"] = ((df["domain_age_days"] >= 0) & (df["domain_age_days"] < 90)).astype(int)
df["ssl_invalid_or_short"] = ((df["ssl_valid"] == 0) | (df["cert_days_left"] < 14)).astype(int)
df["redirect_and_domain_diff"] = ((df["redirect_chain_len"] > 0) & (df["final_domain_differs"] == 1)).astype(int)

# ================== Clean & Split ==================
X = df.drop("label", axis=1).copy()
y = df["label"].astype(int)  # 1 = unsafe, 0 = safe

# บังคับ numeric + จัดการค่าว่าง/inf
X = X.apply(pd.to_numeric, errors="coerce")
X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

# ---- NEW: ตรวจจำนวนคลาสก่อน split ----
value_counts = y.value_counts().to_dict()
print("Class counts:", value_counts)  # debug ดูจำนวนของแต่ละคลาส

min_class = min(value_counts.values()) if len(value_counts) > 0 else 0

# เงื่อนไขที่ยอมใช้ stratify:
# - มีครบทั้งสองคลาส
# - คลาสที่น้อยสุด >= 2
# - และขนาดเทสเซ็ตของคลาสน้อยสุด >= 1 (ประมาณคร่าวๆ)
TEST_SIZE = 0.2
use_stratify = (
    set(value_counts.keys()) == {0, 1} and
    min_class >= 2 and
    int(round(min_class * TEST_SIZE)) >= 1
)

if use_stratify:
    stratify_arg = y
    print("Split mode: stratified")
else:
    stratify_arg = None
    print("Split mode: NON-stratified (fallback, because minority class too small)")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=TEST_SIZE, stratify=stratify_arg, random_state=42
)


# ================== Train RandomForest ==================
clf = RandomForestClassifier(
    n_estimators=1200,
    max_depth=None,
    min_samples_split=4,
    min_samples_leaf=1,
    max_features="sqrt",
    bootstrap=True,
    oob_score=True,
    max_samples=0.9,
    class_weight={0: 1.0, 1: 1.3},  # 1 = unsafe (เพิ่มน้ำหนักเพื่อลด false negative)
    random_state=42,
    n_jobs=-1
)
clf.fit(X_train, y_train)
print("OOB score:", round(clf.oob_score_, 4))

# ================== Evaluate @0.5 (robust to single-class) ==================
# บางครั้งเมื่อข้อมูลน้อย y_train อาจมีคลาสเดียว → predict_proba จะมี 1 คอลัมน์
proba_all = clf.predict_proba(X_test)

if proba_all.shape[1] == 1:
    # โมเดลรู้จักคลาสเดียว
    only_class = int(clf.classes_[0])
    if only_class == 1:
        # ถ้าคลาสเดียวคือ "unsafe" ให้ถือว่า proba_unsafe = คอลัมน์เดียวที่ได้มา
        proba = proba_all[:, 0]
    else:
        # ถ้าคลาสเดียวคือ "safe" ให้ proba_unsafe = 0 ทั้งหมด
        proba = np.zeros(len(X_test), dtype=float)
else:
    # มีครบสองคลาส → หา index ของคลาส 1 (unsafe)
    unsafe_idx = int(np.where(clf.classes_ == 1)[0][0])
    proba = proba_all[:, unsafe_idx]

pred_05 = (proba >= 0.5).astype(int)
print("\n🎯 Accuracy @0.5:", round(accuracy_score(y_test, pred_05), 4))
print("\n📊 Report @0.5:\n",
      classification_report(y_test, pred_05, target_names=["safe","unsafe"], digits=4))


# ================== Threshold Scan (เลือก F1 ดีสุดภายใต้ recall ≥ TARGET_RECALL) ==================
scan_rows = []
for thr in THRESH_GRID:
    pred = (proba >= thr).astype(int)
    prec1 = precision_score(y_test, pred, pos_label=1, zero_division=0)
    rec1  = recall_score(y_test, pred, pos_label=1, zero_division=0)
    f1_1  = f1_score(y_test, pred, pos_label=1, zero_division=0)
    acc   = accuracy_score(y_test, pred)
    scan_rows.append({"threshold": float(thr),
                      "precision_unsafe": float(prec1),
                      "recall_unsafe": float(rec1),
                      "f1_unsafe": float(f1_1),
                      "accuracy": float(acc)})

scan_df = pd.DataFrame(scan_rows)
scan_csv_path = os.path.join(plot_dir, "threshold_scan.csv")
scan_df.to_csv(scan_csv_path, index=False)

# คัดกรองจุดที่ recall >= TARGET_RECALL แล้วเลือก f1 ที่สูงสุด
candidates = scan_df[scan_df["recall_unsafe"] >= TARGET_RECALL]
if len(candidates) == 0:
    # ถ้าไม่มีจุดไหนทำ recall ถึง target → เลือก threshold ที่ recall สูงสุด แล้วค่อยดู f1/precision
    best_row = scan_df.sort_values(["recall_unsafe","f1_unsafe","precision_unsafe"], ascending=[False, False, False]).iloc[0]
else:
    best_row = candidates.sort_values(["f1_unsafe","precision_unsafe","accuracy"], ascending=[False, False, False]).iloc[0]

best_thr = float(best_row["threshold"])
print(f"\n🔧 Tuned threshold (recall≥{TARGET_RECALL}, best F1_unsafe): {best_thr:.3f}")

tuned_pred = (proba >= best_thr).astype(int)
print("\n📊 Report @tuned:\n",
      classification_report(y_test, tuned_pred, target_names=["safe","unsafe"], digits=4))

# ================== Curves & Plots ==================
# PR curve (global) — AP คำนวณได้แม้ y_test จะมีคลาสเดียว แต่ให้รับมือไว้
ap = average_precision_score(y_test, proba)
prec_curve, rec_curve, _ = precision_recall_curve(y_test, proba)
plt.figure()
plt.plot(rec_curve, prec_curve)
plt.xlabel("Recall"); plt.ylabel("Precision")
plt.title(f"Precision-Recall (AP={ap:.3f})")
plt.tight_layout()
plt.savefig(os.path.join(plot_dir, "pr_curve.png"))
plt.close()

# ROC — ต้องมีทั้งสองคลาสใน y_test
if len(np.unique(y_test)) == 2:
    fpr, tpr, _ = roc_curve(y_test, proba)
    roc_auc = roc_auc_score(y_test, proba)
    plt.figure()
    plt.plot(fpr, tpr)
    plt.xlabel("FPR"); plt.ylabel("TPR")
    plt.title(f"ROC (AUC={roc_auc:.3f})")
    plt.tight_layout()
    plt.savefig(os.path.join(plot_dir, "roc_curve.png"))
    plt.close()
else:
    roc_auc = float("nan")
    print("⚠️ ROC AUC skipped: y_test มีคลาสเดียว")

# Confusion @ tuned (รันได้แม้คลาสเดียว)
cm = confusion_matrix(y_test, tuned_pred)
...

plt.figure(figsize=(6,4))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=["safe","unsafe"], yticklabels=["safe","unsafe"])
plt.xlabel("Predicted"); plt.ylabel("True")
plt.title(f"Confusion Matrix (thr={best_thr:.3f})")
plt.tight_layout()
plt.savefig(os.path.join(plot_dir, "confusion_matrix_tuned.png"))
plt.close()

# Feature Importances (Tree-based)
importances = clf.feature_importances_
indices = np.argsort(importances)[::-1]
topk = min(30, len(indices))
plt.figure(figsize=(12,6))
sns.barplot(x=importances[indices][:topk], y=X.columns[indices][:topk])
plt.title("Top 30 Feature Importances (RF)")
plt.tight_layout()
plt.savefig(os.path.join(plot_dir, "feature_importance.png"))
plt.close()

# Permutation Importance
perm = permutation_importance(clf, X_test, y_test, n_repeats=5, random_state=42, n_jobs=-1)
pi_sorted = np.argsort(perm.importances_mean)[::-1][:topk]
plt.figure(figsize=(12,6))
sns.barplot(x=perm.importances_mean[pi_sorted], y=X.columns[pi_sorted])
plt.title("Top 30 Permutation Importances")
plt.tight_layout()
plt.savefig(os.path.join(plot_dir, "perm_importance.png"))
plt.close()

# ================== Helper: สร้าง "ตารางสรุปผลแบบรูปภาพ" ==================
def save_report_table(y_true, y_pred, out_png_path, digits=2):
    """
    สร้างรูปภาพตารางสรุปผล (precision/recall/f1/support + accuracy, macro avg, weighted avg)
    """
    rep = classification_report(
        y_true, y_pred, target_names=["safe","unsafe"], digits=digits, output_dict=True
    )

    rows_order = ["safe", "unsafe", "accuracy", "macro avg", "weighted avg"]
    cols_order = ["precision", "recall", "f1-score", "support"]

    table_data = []
    for r in rows_order:
        if r == "accuracy":
            acc = rep["accuracy"]
            row = [acc, acc, acc, rep["safe"]["support"] + rep["unsafe"]["support"]]
        else:
            row = [
                rep[r]["precision"],
                rep[r]["recall"],
                rep[r]["f1-score"],
                rep[r]["support"],
            ]
        table_data.append(row)

    df_report = pd.DataFrame(table_data, index=rows_order, columns=cols_order)
    df_report[["precision","recall","f1-score"]] = df_report[["precision","recall","f1-score"]].astype(float).round(digits)
    df_report["support"] = df_report["support"].astype(float).round(1)

    fig, ax = plt.subplots(figsize=(7, 2.6))
    ax.axis('off')
    tbl = ax.table(
        cellText=df_report.values,
        rowLabels=df_report.index,
        colLabels=df_report.columns,
        loc='center',
        cellLoc='center',
        rowLoc='center'
    )
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(10)
    tbl.scale(1, 1.2)
    plt.tight_layout()
    plt.savefig(out_png_path, dpi=200, bbox_inches='tight')
    plt.close()

# สร้างตารางแบบภาพทั้งสอง threshold
save_report_table(y_test, pred_05,   os.path.join(plot_dir, "classification_report_0p5.png"))
save_report_table(y_test, tuned_pred, os.path.join(plot_dir, "classification_report_tuned.png"))
print(f"✅ Saved report tables to {plot_dir}")

# ================== Save model + feature order + metrics ==================
model_dir = os.path.dirname(__file__)
model_path = os.path.join(model_dir, "phishing_model.pkl")
joblib.dump(clf, model_path)

# สำคัญ: บันทึกลำดับคอลัมน์ EXACT ตาม X.columns เพื่อให้ app.py ใช้ตอน build_feature_row
with open(os.path.join(model_dir, "feature_order.json"), "w", encoding="utf-8") as f:
    json.dump(list(X.columns), f, ensure_ascii=False, indent=2)

metrics_path = os.path.join(model_dir, "metrics.json")
with open(metrics_path, "w", encoding="utf-8") as f:
    json.dump({
        "oob_score": float(clf.oob_score_),
        "accuracy@0.5": float(accuracy_score(y_test, pred_05)),
        "roc_auc": float(roc_auc),
        "avg_precision": float(ap),
        "tuned_threshold": float(best_thr),
        "tuned_report": classification_report(
            y_test, tuned_pred, target_names=["safe","unsafe"], digits=4, output_dict=True
        ),
        "target_recall": float(TARGET_RECALL),
        "threshold_scan_csv": scan_csv_path
    }, f, ensure_ascii=False, indent=2)

print(f"\n✅ Model saved to {model_path}")
print(f"✅ Metrics saved to {metrics_path}")
print(f"✅ Threshold scan saved to {scan_csv_path}")
print(f"✅ Plots saved to: {plot_dir}")
