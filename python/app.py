# app.py
import os, sys, json, traceback
from datetime import datetime
from urllib.parse import urlparse

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

import joblib
import pandas as pd
import numpy as np
from treeinterpreter import treeinterpreter as ti

# ---------------- PATHS ----------------
app_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(app_dir, ".."))
template_dir = os.path.join(project_root, "templates")

# หาโฟลเดอร์ที่ "เขียนได้จริง"
def _ensure_writable_dir(candidates):
    for d in candidates:
        try:
            os.makedirs(d, exist_ok=True)
            test_path = os.path.join(d, ".write_test")
            with open(test_path, "w", encoding="utf-8") as f:
                f.write("ok")
            os.remove(test_path)
            return d
        except Exception as e:
            print(f"[BOOT] dir not writable -> {d} ({e})")
    return None

db_dir = _ensure_writable_dir([
    os.path.join(project_root, "database"),
    "/tmp/appdata/database",
]) or "/tmp"

model_path = os.path.join(app_dir, "phishing_model.pkl")
feature_order_path = os.path.join(app_dir, "feature_order.json")
log_file_path = os.path.join(db_dir, "result_log.json")

print(f"[BOOT] db_dir   = {db_dir}")
print(f"[BOOT] log_file = {log_file_path}")

# ---------------- FLASK ----------------
app = Flask(__name__, template_folder=template_dir)
CORS(app)

# ---------------- LOAD MODEL/FEATURES ----------------
if not os.path.exists(model_path):
    raise FileNotFoundError(f"ไม่พบโมเดลที่ {model_path}")

model = joblib.load(model_path)

if os.path.exists(feature_order_path):
    with open(feature_order_path, "r", encoding="utf-8") as f:
        FEATURE_ORDER = json.load(f)
else:
    FEATURE_ORDER = None

# ---------------- IMPORT url_checker ----------------
# สำคัญ: url_checker ต้องไม่มี Selenium init ตอน import
sys.path.append(app_dir)
from url_checker import analyze_full_url  # ใช้เวอร์ชันที่ normalize URL ข้างในแล้ว ถ้ามี
# เพิ่ม normalize_url แบบ local เผื่อ url_checker ยังไม่ได้ normalize
import re
def normalize_url(u: str) -> str:
    u = (u or "").strip()
    if not u:
        return u
    if not u.startswith(("http://", "https://")):
        if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/|$)", u):
            return "https://" + u
        return "http://" + u
    return u

# ---------------- HUMAN READABLE ----------------
HUMAN_READABLE = {
    "length_url": "ความยาวรวมของ URL",
    "length_hostname": "ความยาวชื่อโดเมน",
    "ip": "ใช้ตัวเลขเป็น IP แทนโดเมน",
    "punycode": "โดเมนใช้ Punycode (xn--)",
    "ratio_digits_url": "จำนวนตัวเลขที่ปรากฏใน URL",
    "ratio_digits_host": "จำนวนตัวเลขที่ปรากฏในชื่อโดเมน",
    "nb_subdomains": "จำนวน subdomain ที่อยู่หน้าชื่อโดเมนหลัก",
    "tld_in_path": "มี TLD (เช่น .com) ไปโผล่ใน path",
    "tld_in_subdomain": "มี TLD ไปโผล่ใน subdomain",
    "random_domain": "ชื่อโดเมนมีลักษณะสุ่ม/ใส่ตัวเลข",
    "shortening_service": "เป็น URL แบบย่อ (bit.ly ฯลฯ)",
    "path_extension": "ไฟล์แนบเสี่ยง (.exe, .zip, .php ฯลฯ)",
    "prefix_suffix": "ชื่อโดเมนมีขีดกลาง (-)",
    "phish_hints": "มีคำที่น่าสงสัย (login, verify, account ฯลฯ)",
    "url_entropy": "ความซับซ้อนของ URL",
    "uses_https": "ใช้ HTTPS (เข้ารหัส)",
    "is_http": "ใช้ HTTP ธรรมดา (ไม่เข้ารหัส)",
    "num_query_params": "จำนวน query parameters",
    "has_at_symbol": "มีสัญลักษณ์ @ ใน URL",
    "ssl_valid": "ใบรับรอง SSL ใช้งานได้",
    "cert_days_left": "จำนวนวันก่อน SSL หมดอายุ",
    "san_count": "จำนวนชื่อโดเมนในใบรับรอง SSL (SAN)",
    "cert_cn_matches_domain": "ชื่อโดเมนตรงกับข้อมูลในใบรับรอง SSL",
    "domain_age_days": "อายุโดเมน (วัน)",
    "tld_risk": "ความเสี่ยงของ TLD",
    "days_since_update": "จำนวนวันตั้งแต่ update ล่าสุด",
    "has_whois_privacy": "ปิดบังข้อมูล WHOIS",
    "redirect_chain_len": "จำนวนครั้งที่มีการ redirect",
    "final_domain_differs": "redirect ไปโดเมนอื่น",
    "has_security_headers": "มี Security Headers",
    "typosquat_candidate": "ชื่อคล้ายโดเมนดัง (typosquat)",
    "typosquat_score_max": "ความคล้ายกับชื่อโดเมนน่าเชื่อถือ (สูงสุด)",
    "typosquat_score_mean": "ความคล้ายกับชื่อโดเมนน่าเชื่อถือ (เฉลี่ย)",
    "typosquat_distance": "ระยะห่างชื่อโดเมนกับของจริง",
    # engineered
    "url_length_ratio": "ความยาว URL เทียบกับความยาวโดเมน",
    "digit_ratio_diff": "ความต่างปริมาณตัวเลขระหว่าง URL และโดเมน",
    "domain_age_lt_90d": "อายุโดเมนน้อยกว่า 90 วัน",
    "ssl_invalid_or_short": "SSL ไม่พร้อมใช้งาน/จะหมดอายุในระยะสั้น",
    "redirect_and_domain_diff": "มี redirect และปลายทางเป็นโดเมนอื่น",
}

BOOL_FEATS = {
    "ssl_valid","uses_https","is_http","ip","punycode","shortening_service","prefix_suffix",
    "tld_in_path","tld_in_subdomain","random_domain","phish_hints","has_at_symbol",
    "domain_age_lt_90d","ssl_invalid_or_short","redirect_and_domain_diff",
    "typosquat_candidate","has_whois_privacy","final_domain_differs","has_security_headers"
}

REDIRECT_FEATS = {"redirect_chain_len", "final_domain_differs", "redirect_and_domain_diff"}

# ---------------- HELPERS ----------------
def to_float(x, default=0.0):
    try: return float(x)
    except: return default

def to_int01(x):
    if x in (True, 1, "1"): return 1
    if x in (False, 0, "0"): return 0
    try: return 1 if float(x) != 0 else 0
    except: return 0

def build_feature_row(features_dict, feature_order):
    row = []
    for feat in feature_order:
        val = features_dict.get(feat, None)
        if feat == "domain_age_days":
            row.append(-1 if val is None else to_float(val, -1))
        elif feat in BOOL_FEATS:
            row.append(to_int01(val))
        else:
            row.append(to_float(val, 0.0))
    return row

def friendly_value(feat, v):
    if feat in BOOL_FEATS:
        return "พบ" if to_int01(v)==1 else "ไม่พบ"
    if feat == "cert_cn_matches_domain":
        return "ตรง" if to_int01(v)==1 else "ไม่ตรง"
    return f"{v}"

def make_explanation(feat_key, label, value_str, c):
    neg = c < 0
    if feat_key == "domain_age_days":
        return f"โดเมนเปิดใช้งานมานาน ({value_str} วัน)" if neg else f"อายุโดเมนยังใหม่ ({value_str} วัน)"
    if feat_key == "ssl_valid":
        return "พบใบรับรอง SSL ที่ใช้งานได้" if neg else "ไม่พบ/ไม่สามารถยืนยันใบรับรอง SSL"
    if feat_key == "cert_days_left":
        return f"ใบรับรอง SSL ยังมีอายุ {value_str} วัน" if neg else f"ใบรับรอง SSL ใกล้หมดอายุ ({value_str} วัน)"
    if feat_key == "san_count":
        return f"ใบรับรอง SSL ครอบคลุมหลายโดเมน ({value_str} รายการ)" if neg else f"ใบรับรอง SSL ครอบคลุมน้อย ({value_str} รายการ)"
    if feat_key == "cert_cn_matches_domain":
        return "ชื่อโดเมนสอดคล้องกับใบรับรอง SSL" if value_str == "ตรง" else "ชื่อโดเมนไม่ตรงกับใบรับรอง SSL"
    if feat_key in REDIRECT_FEATS:
        return "ไม่พบการเปลี่ยนเส้นทางน่าสงสัย" if neg else "มีการเปลี่ยนเส้นทางหลายครั้ง/ไปยังโดเมนอื่น"
    return f"{label}: {value_str}"

def _coalesce_reasons(reasons):
    grouped = {}
    for r in reasons:
        key = r["feature"]
        r2 = dict(r)
        if r["feature"] in REDIRECT_FEATS:
            direction_key = "neg" if r["contribution"] < 0 else "pos"
            key = f"redirect_group_{direction_key}"
            r2["label"] = "พฤติกรรมการเปลี่ยนเส้นทาง"
            if r["contribution"] < 0:
                r2["explanation"] = "ไม่พบการเปลี่ยนเส้นทางผิดปกติ"
                r2["value"] = "ปกติ"
            else:
                r2["explanation"] = "พบการเปลี่ยนเส้นทางที่อาจผิดปกติ (หลายครั้งหรือไปต่างโดเมน)"
                r2["value"] = "ผิดปกติ"
        prev = grouped.get(key)
        if (prev is None) or (abs(r2["contribution"]) > abs(prev["contribution"])):  # pick the stronger one
            grouped[key] = r2
    merged = list(grouped.values())
    merged.sort(key=lambda x: abs(x["contribution"]), reverse=True)
    return merged

def pick_top_reasons(feature_names, values_dict, contribs_for_unsafe, final_label, top_k=5):
    pairs = list(zip(feature_names, contribs_for_unsafe))
    if final_label == "unsafe":
        pairs = [p for p in pairs if p[1] > 0]
        pairs.sort(key=lambda x: x[1], reverse=True)
    else:
        pairs = [p for p in pairs if p[1] < 0]
        pairs.sort(key=lambda x: x[1])
    reasons = []
    for feat, c in pairs:
        label = HUMAN_READABLE.get(feat, feat)
        raw_v = values_dict.get(feat, None)
        v_str = friendly_value(feat, raw_v)
        explanation = make_explanation(feat, label, v_str, c)
        reasons.append({
            "feature": feat,
            "label": label,
            "value": v_str,
            "contribution": float(c),
            "explanation": explanation
        })
    reasons = _coalesce_reasons(reasons)
    return reasons[:top_k]

def classify_band(prob_unsafe: float):
    if prob_unsafe < 0.35:
        return "safe"
    if prob_unsafe < 0.65:
        return "suspicious"
    return "unsafe"

def result_message(label: str, host: str):
    if label == "safe":
        return f"{host} ไม่พบสัญญาณผิดปกติชัดเจน โปรดใช้งานอย่างระมัดระวังตามปกติ"
    if label == "suspicious":
        return f"{host} มีบางสัญญาณที่ควรระวัง แนะนำให้หลีกเลี่ยงการกรอกข้อมูลสำคัญจนกว่าจะยืนยันได้แน่ชัด"
    return f"{host} มีความเสี่ยงสูง ไม่ควรกรอกข้อมูลส่วนตัวหรือดาวน์โหลดไฟล์จากเว็บไซต์นี้"

def build_website_info(feats: dict) -> dict:
    """เลือกเฉพาะข้อมูลสำคัญมาแสดง และซ่อนค่าที่ไม่จำเป็น"""
    parsed = urlparse(feats.get("url", ""))
    host = parsed.netloc or feats.get("url", "")
    info = {"โดเมน": host}

    if feats.get("domain_age_days", -1) >= 0:
        info["อายุโดเมน (วัน)"] = feats["domain_age_days"]

    if feats.get("uses_https", 0) != 1:
        info["ใช้ HTTPS"] = "ไม่ใช่"

    if feats.get("ssl_valid", 0) != 1:
        info["ใบรับรอง SSL"] = "ไม่พบ/ไม่ถูกต้อง"
    else:
        if feats.get("cert_days_left", 0) <= 30:
            info["SSL ใกล้หมดอายุ (วัน)"] = feats.get("cert_days_left", 0)

    if feats.get("redirect_chain_len", 0) > 0:
        info["จำนวนครั้งที่มีการ redirect"] = feats.get("redirect_chain_len", 0)
    if feats.get("final_domain_differs", 0) == 1:
        info["redirect ไปโดเมนอื่น"] = "มี"

    # ถ้า url_checker ของคุณเติมฟิลด์จาก Selenium เช่น current_url/redirect_chain แล้วอยากโชว์ก็เพิ่มได้:
    if feats.get("selenium_current_url"):
        info["ปลายทางล่าสุด (เบราว์เซอร์)"] = feats["selenium_current_url"]

    return info

# ---------------- LOG SAVE (atomic + fallback) ----------------
def save_log_record(record: dict) -> str:
    try:
        os.makedirs(db_dir, exist_ok=True)
        logs = []
        if os.path.exists(log_file_path) and os.path.getsize(log_file_path) > 0:
            try:
                with open(log_file_path, "r", encoding="utf-8") as f:
                    logs = json.load(f)
                    if not isinstance(logs, list):
                        logs = []
            except Exception as e:
                print(f"[LOG] read error -> reset: {e}")
        logs.append(record)
        tmp_path = log_file_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(logs, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, log_file_path)
        print(f"[LOG] appended -> {log_file_path}")
        return log_file_path
    except Exception as e:
        print(f"[LOG] write error: {e}")
        try:
            fb_dir = "/tmp/appdata/database"
            os.makedirs(fb_dir, exist_ok=True)
            fb_path = os.path.join(fb_dir, "result_log.json")
            existing = []
            if os.path.exists(fb_path) and os.path.getsize(fb_path) > 0:
                try:
                    with open(fb_path, "r", encoding="utf-8") as f:
                        existing = json.load(f)
                        if not isinstance(existing, list):
                            existing = []
                except:
                    existing = []
            existing.append(record)
            with open(fb_path, "w", encoding="utf-8") as f:
                json.dump(existing, f, ensure_ascii=False, indent=2)
            print(f"[LOG] appended (fallback) -> {fb_path}")
            return fb_path
        except Exception as e2:
            print(f"[LOG] fallback write error: {e2}")
            return ""

# ---------------- ROUTES ----------------
@app.route("/", methods=["GET"])
def home():
    index_path = os.path.join(template_dir, "index.html")
    if os.path.exists(index_path):
        return render_template("index.html")
    return jsonify({"ok": True, "message": "Phishing URL API with XAI is running."})

@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok"})

@app.route("/check_url/", methods=["POST"])
def check_url():
    try:
        data = request.get_json(silent=True) or {}
        url = (data.get("url") or "").strip()
        if not url:
            return jsonify({"ok": False, "error": "กรุณาส่ง url"}), 400

        # 1) Normalize + Extract features
        url_norm = normalize_url(url)   # <<< สำคัญ: ให้มี scheme เสมอ
        feats = analyze_full_url(url_norm)  # url_checker ควร normalize ข้างในด้วยแล้ว แต่ใส่ซ้ำไม่เสียหาย
        if feats.get("domain_age_days") is None:
            feats["domain_age_days"] = -1

        # 2) Engineered features
        feats["url_length_ratio"] = feats.get("length_url", 0) / (feats.get("length_hostname", 0) + 1)
        feats["digit_ratio_diff"] = abs(feats.get("ratio_digits_url", 0) - feats.get("ratio_digits_host", 0))
        feats["domain_age_lt_90d"] = 1 if feats.get("domain_age_days", -1) < 90 and feats.get("domain_age_days", -1) >= 0 else 0
        feats["ssl_invalid_or_short"] = 1 if (feats.get("ssl_valid", 0) == 0 or feats.get("cert_days_left", 0) < 14) else 0
        feats["redirect_and_domain_diff"] = 1 if (feats.get("redirect_chain_len", 0) > 0 and feats.get("final_domain_differs", 0) == 1) else 0

        # 3) Build row
        feature_order = FEATURE_ORDER or [k for k in feats.keys() if k != "label"]
        row = build_feature_row(feats, feature_order)
        X = pd.DataFrame([row], columns=feature_order)

        # 4) Predict -> รองรับกรณีโมเดลมีคลาสเดียว
        classes = getattr(model, "classes_", None)
        if hasattr(model, "predict_proba") and classes is not None:
            proba = model.predict_proba(X)[0]
            if len(classes) == 2:
                # หาตำแหน่งของ class=1 ให้ชัดเจน
                if 1 in classes:
                    idx1 = int(np.where(classes == 1)[0][0])
                else:
                    # fallback ปกติ scikit จะเป็น [0,1] อยู่แล้ว
                    idx1 = 1
                unsafe_p = float(proba[idx1])
            else:
                # single-class model → proba มีค่าเดียว
                only = int(classes[0])
                unsafe_p = 1.0 if only == 1 else 0.0
        else:
            pred = int(model.predict(X)[0])
            unsafe_p = 1.0 if pred == 1 else 0.0

        final_label = classify_band(unsafe_p)

        # 5) XAI (treeinterpreter) → มี fallback เมื่อเป็น single-class หรือใช้ไม่ได้
        reasons = []
        bias_val = 0.0

        def _fallback_reasons_by_rules(feature_order, feats, importances, top_k=5):
            # 1) กฎพื้นฐาน: true = เสี่ยง
            risky_rules = {
                "uses_https":              lambda v: v == 0,
                "ssl_valid":               lambda v: v == 0,
                "cert_days_left":          lambda v: v < 14,
                "domain_age_days":         lambda v: (v >= 0 and v < 90),
                "redirect_chain_len":      lambda v: v > 0,
                "final_domain_differs":    lambda v: v == 1,
                "has_at_symbol":           lambda v: v == 1,
                "shortening_service":      lambda v: v == 1,
                "phish_hints":             lambda v: v == 1,
                "tld_risk":                lambda v: v == 1,
                "url_entropy":             lambda v: v > 4.0,
                "length_url":              lambda v: v > 80,
                "num_query_params":        lambda v: v > 3,
                "prefix_suffix":           lambda v: v == 1,
                "random_domain":           lambda v: v == 1,
                "typosquat_candidate":     lambda v: v == 1,
                "ssl_invalid_or_short":    lambda v: v == 1,
                "redirect_and_domain_diff":lambda v: v == 1,
            }

            # 2) น้ำหนักสำรองถ้าไม่มี/เป็นศูนย์ทั้งหมด
            default_weights = {
                "ssl_valid": 1.0, "uses_https": 0.9, "ssl_invalid_or_short": 0.9,
                "cert_days_left": 0.8, "domain_age_days": 0.8, "domain_age_lt_90d": 0.8,
                "final_domain_differs": 0.8, "redirect_and_domain_diff": 0.75, "redirect_chain_len": 0.6,
                "phish_hints": 0.8, "typosquat_candidate": 0.7, "random_domain": 0.7,
                "length_url": 0.55, "url_entropy": 0.55, "num_query_params": 0.5,
                "shortening_service": 0.5, "has_at_symbol": 0.45, "prefix_suffix": 0.45,
                "tld_risk": 0.5,
            }

            # 3) เตรียมน้ำหนักที่จะใช้
            use_default = True
            weights = {}
            if importances is not None:
                try:
                    imp_arr = np.asarray(importances).astype(float)
                    if np.any(imp_arr > 0):
                        use_default = False
                        for i, feat in enumerate(feature_order):
                            if feat == "label": 
                                continue
                            w = float(imp_arr[i]) if i < len(imp_arr) else 0.0
                            weights[feat] = w
                except Exception:
                    use_default = True

            if use_default:
                # ใช้น้ำหนักสำรองตาม domain knowledge
                for feat in feature_order:
                    if feat == "label": 
                        continue
                    weights[feat] = default_weights.get(feat, 0.2)

            # 4) สร้างรายการสรุป โดยไม่กรอง w==0 ทิ้ง เพื่อให้มีเหตุผลเสมอ
            scored = []
            for feat in feature_order:
                if feat == "label": 
                    continue
                v = feats.get(feat, 0)
                w = float(weights.get(feat, 0.2))
                is_risky = risky_rules.get(feat, lambda _: False)(v)
                # เสี่ยง = บวก, ไม่เสี่ยง = ลบ (เล็กกว่า)
                score = w * (1.0 if is_risky else -0.4)
                label = HUMAN_READABLE.get(feat, feat)
                expl = f"{label}: {'เข้าข่ายเสี่ยง' if is_risky else 'ไม่มีสัญญาณเสี่ยงชัดเจน'}"
                scored.append({
                    "feature": feat,
                    "label": label,
                    "value": friendly_value(feat, v),
                    "score": score,
                    "explanation": expl
                })

            # จัดอันดับ → เอา “เสี่ยง” ก่อน แล้วค่อย “ไม่เสี่ยง”
            scored.sort(key=lambda x: x["score"], reverse=True)

            # ถ้าไม่มีอะไรเสี่ยงเลย ให้ดึง 3 รายการ “ปลอดภัย” อันดับต้น ๆ มาช่วยอธิบาย
            positives = [s for s in scored if s["score"] > 0]
            if not positives:
                positives = [s for s in scored if s["score"] < 0][:3]

            out = []
            for r in positives[:top_k]:
                out.append({
                    "feature": r["feature"],
                    "label": r["label"],
                    "value": r["value"],
                    "contribution": float(r["score"]),
                    "explanation": r["explanation"]
                })
            return out

        try:
            # พยายามใช้ treeinterpreter ก่อน
            _, bias, contribs = ti.predict(model, X.values)
            classes = getattr(model, "classes_", None)
            if contribs.ndim == 3 and classes is not None and (len(classes) >= 2) and (1 in classes):
                idx1 = int(np.where(classes == 1)[0][0])
                contrib_unsafe = contribs[0, :, idx1]
                reasons = pick_top_reasons(
                    feature_order, feats, contrib_unsafe,
                    "unsafe" if unsafe_p >= 0.5 else "safe",
                    top_k=5
                )
                bias_val = float(bias[0, idx1])
            else:
                # ❗ Fallback: ใช้ importances + rules (แบบใหม่)
                importances = getattr(model, "feature_importances_", None)
                reasons = _fallback_reasons_by_rules(feature_order, feats, importances, top_k=5)
                bias_val = 0.0
        except Exception:
            # ถ้า XAI พังทั้งหมด → fallback เช่นกัน
            importances = getattr(model, "feature_importances_", None)
            reasons = _fallback_reasons_by_rules(feature_order, feats, importances, top_k=5)
            bias_val = 0.0


        # 6) Website Info
        website_info = build_website_info(feats)

        # 7) Message
        parsed = urlparse(feats.get("url", url_norm))
        host = parsed.netloc or feats.get("url", url_norm)
        message = result_message(final_label, host)

        # 8) Log
        record = {
            "url": feats.get("url", url_norm),
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "result": final_label,
            "unsafe_probability": round(unsafe_p, 4),
            "reasons": reasons,
            "website_info": website_info,
        }
        log_path_used = save_log_record(record)

        # 9) Response
        return jsonify({
            "ok": True,
            "url": feats.get("url", url_norm),
            "timestamp": datetime.utcnow().isoformat(),
            "result": final_label,
            "message": message,
            "website_info": website_info,
            "reasons": reasons,
            "bias": bias_val,
            "log_path": log_path_used,
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/disclaimerPopup.html", methods=["GET"])
def disclaimer_popup():
    return render_template("disclaimerPopup.html")

@app.route("/save_disclaimer", methods=["POST"])
def save_disclaimer():
    try:
        data = request.get_json()
        disclaimer_file_path = os.path.join(db_dir, "disclaimer.json")
        if os.path.exists(disclaimer_file_path):
            with open(disclaimer_file_path, "r", encoding="utf-8") as f:
                try:
                    disclaimers = json.load(f)
                except json.JSONDecodeError:
                    disclaimers = []
        else:
            disclaimers = []
        disclaimers.append(data)
        with open(disclaimer_file_path, "w", encoding="utf-8") as f:
            json.dump(disclaimers, f, ensure_ascii=False, indent=2)
        return jsonify({"ok": True, "message": "ข้อมูลถูกบันทึกแล้ว!"}), 200
    except Exception as e:
        print(f"Error saving disclaimer: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500

if __name__ == "__main__":
    print("📂 template_dir:", template_dir)
    print("📦 model_path:", model_path)
    app.run(host="0.0.0.0", port=5000, debug=True)
