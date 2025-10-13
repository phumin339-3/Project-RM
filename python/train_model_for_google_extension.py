# train_model_for_google_extension.py (updated)
import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

# ================== CONFIG ==================
RANDOM_STATE = 42
TEST_SIZE = 0.2

# ================== Paths ==================
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../Feature_ML"))
phish_path = os.path.join(base_dir, "phishing_urls.csv")
legit_path = os.path.join(base_dir, "legitimate_urls.csv")

out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__)))
model_path = os.path.join(out_dir, "extension.pkl")
feature_order_path = os.path.join(out_dir, "extension_feature_order.json")

# ================== Load data ==================
phish_df = pd.read_csv(phish_path)
legit_df = pd.read_csv(legit_path)

if "label" not in phish_df.columns:
    phish_df["label"] = 1
if "label" not in legit_df.columns:
    legit_df["label"] = 0

df_raw = pd.concat([phish_df, legit_df], ignore_index=True)

print(f"✅ Loaded phishing URLs: {len(phish_df)}, legitimate URLs: {len(legit_df)}")
print(f"✅ Total dataset size: {len(df_raw)}")

# ================== Features ==================
extension_features = [
    "length_url", "length_hostname", "ratio_digits_url", "ratio_digits_host",
    "nb_subdomains", "tld_in_path", "tld_in_subdomain", "shortening_service",
    "prefix_suffix", "url_entropy", "uses_https", "is_http", "num_query_params",
    "has_at_symbol", "path_extension", "tld_risk",
    "typosquat_candidate", "typosquat_score_max", "typosquat_score_mean", "typosquat_distance",
    "label"
]

# ================== Defaults ==================
defaults = {
    "length_url": 0, "length_hostname": 0, "ratio_digits_url": 0.0, "ratio_digits_host": 0.0,
    "nb_subdomains": 0, "tld_in_path": 0, "tld_in_subdomain": 0, "shortening_service": 0,
    "prefix_suffix": 0, "url_entropy": 0.0, "uses_https": 0, "is_http": 0, "num_query_params": 0,
    "has_at_symbol": 0, "path_extension": 0, "tld_risk": 0,
    "typosquat_candidate": 0,
    "typosquat_score_max": 0, "typosquat_score_mean": 0, "typosquat_distance": 0,
}

for col in extension_features:
    if col == "label":
        continue
    if col not in df_raw.columns:
        df_raw[col] = defaults.get(col, 0)

df = df_raw[[c for c in extension_features if c in df_raw.columns]].copy()

# ================== Extra client-side features ==================
df["url_length_ratio"] = df["length_url"] / (df["length_hostname"] + 1)
df["digit_ratio_diff"] = (df["ratio_digits_url"] - df["ratio_digits_host"]).abs()

# ================== Prepare X, y ==================
if "label" not in df.columns:
    raise RuntimeError("label column not found in input CSVs — cannot train")

X = df.drop("label", axis=1).copy()
y = df["label"].astype(int)

X = X.apply(pd.to_numeric, errors="coerce")
X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

# ================== Train/Test split ==================
value_counts = y.value_counts().to_dict()
min_class = min(value_counts.values()) if len(value_counts) > 0 else 0
use_stratify = (set(value_counts.keys()) == {0, 1} and min_class >= 2 and int(round(min_class * TEST_SIZE)) >= 1)
stratify_arg = y if use_stratify else None

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=TEST_SIZE, stratify=stratify_arg, random_state=RANDOM_STATE
)

print(f"✅ Training samples: {len(X_train)}, Testing samples: {len(X_test)}")

# ================== Train RandomForest ==================
clf = RandomForestClassifier(
    n_estimators=500,
    max_depth=None,
    min_samples_split=4,
    min_samples_leaf=1,
    max_features="sqrt",
    bootstrap=True,
    class_weight={0: 1.0, 1: 1.3},
    random_state=RANDOM_STATE,
    n_jobs=-1
)
clf.fit(X_train, y_train)

# ================== Evaluate ==================
y_pred_train = clf.predict(X_train)
y_pred_test = clf.predict(X_test)
train_acc = accuracy_score(y_train, y_pred_train)
test_acc = accuracy_score(y_test, y_pred_test)

print(f"📊 Training accuracy: {train_acc:.4f}")
print(f"📊 Testing accuracy:  {test_acc:.4f}")

# ================== Save model & feature order ==================
joblib.dump(clf, model_path)
feature_order = list(X.columns)
with open(feature_order_path, "w", encoding="utf-8") as f:
    json.dump(feature_order, f, ensure_ascii=False, indent=2)

print(f"✅ Model saved to: {model_path}")
print(f"✅ Feature order saved to: {feature_order_path}")
