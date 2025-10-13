from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import numpy as np
import json
import requests
from urllib.parse import urlparse
from datetime import datetime

app = FastAPI()

# โหลดโมเดล Machine Learning
model = joblib.load("phishing_model.pkl")

# ✅ API Keys
VIRUSTOTAL_API_KEY = "c64e4f214217d6933a538f881882fdb09cf11ea5691ba0588a24dda69b891a0a"
GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyAOY26ThIRKUvkQeIrGUKjTmLDvCob10DY"
WHOIS_API_KEY = "at_7GUYm4WTUlLOQN1Ate1CZlcgpYqeK"

class URLInput(BaseModel):
    url: str

def check_openphish(url):
    """ ตรวจสอบ URL กับฐานข้อมูล OpenPhish """
    try:
        with open("database/openphish.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        # Normalize URL → "domain + path" (ลบ http://, https://, www.)
        parsed_url = urlparse(url)
        normalized_url = parsed_url.netloc.lower() + parsed_url.path.lower()

        for entry in data:
            if "url" in entry:
                stored_url = urlparse(entry["url"]).netloc.lower() + urlparse(entry["url"]).path.lower()
                if stored_url == normalized_url:
                    print(f"⚠️ พบ URL ใน OpenPhish: {stored_url}")  # Debug
                    return "unsafe"

        print(f"✅ URL ไม่พบใน OpenPhish: {normalized_url}")  # Debug
        return "safe"
    except Exception as e:
        print(f"❌ OpenPhish JSON error: {e}")
        return "unknown"

# ✅ ฟังก์ชันตรวจสอบ PhishTank
def check_phishtank(url):
    try:
        with open("database/phishtank.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        normalized_url = url.strip().lower()
        for entry in data:
            if "url" in entry and entry["url"].strip().lower() == normalized_url:
                return "unsafe"

        return "safe"
    except Exception as e:
        print(f"❌ PhishTank JSON error: {e}")
        return "unknown"

# ✅ ฟังก์ชันตรวจสอบ Google Safe Browsing API
def check_google_safe_browsing(url):
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "phishing_detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        response = requests.post(api_url, json=payload, params={"key": GOOGLE_SAFE_BROWSING_API_KEY})
        response.raise_for_status()
        data = response.json()
        return "unsafe" if "matches" in data else "safe"
    except Exception as e:
        print(f"❌ Google Safe Browsing error: {e}")
        return "unknown"

# ✅ ฟังก์ชันตรวจสอบ URLhaus
def check_urlhaus(url):
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    try:
        response = requests.post(api_url, data={"url": url}, timeout=10)
        response.raise_for_status()
        data = response.json()
        return "unsafe" if data.get("query_status") == "malicious" else "safe"
    except Exception as e:
        print(f"❌ URLhaus API error: {e}")
        return "unknown"

# ✅ ฟังก์ชันตรวจสอบ VirusTotal
def check_virustotal(url):
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": "c64e4f214217d6933a538f881882fdb09cf11ea5691ba0588a24dda69b891a0a"}
    data = {"url": url}

    try:
        response = requests.post(api_url, headers=headers, data=data)
        response.raise_for_status()
        result = response.json()
        analysis_id = result["data"]["id"]

        # ดึงผลลัพธ์การสแกน
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        response = requests.get(report_url, headers=headers)
        report_data = response.json()

        if report_data["data"]["attributes"]["stats"]["malicious"] > 0:
            return "unsafe"
        return "safe"
    except Exception as e:
        print(f"❌ VirusTotal API error: {e}")
        return "unknown"

# ✅ ฟังก์ชันตรวจสอบอายุโดเมนผ่าน Whois API
def check_domain_age(url):
    """ ตรวจสอบอายุของโดเมนผ่าน Whois API """
    domain = urlparse(url).netloc

    api_url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService"
    params = {
        "domainName": domain,
        "apiKey": "at_7GUYm4WTUlLOQN1Ate1CZlcgpYqeK",
        "outputFormat": "JSON"
    }

    try:
        response = requests.get(api_url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        creation_date = data.get("WhoisRecord", {}).get("registryData", {}).get("createdDate")

        if creation_date:
            age_days = (datetime.now() - datetime.strptime(creation_date, "%Y-%m-%dT%H:%M:%SZ")).days
            return age_days
        else:
            return None
    except Exception as e:
        print(f"❌ Whois API error: {e}")
        return None

# ✅ ฟังก์ชันใช้ Machine Learning ทำนายผล
def check_ml_model(url):
    features = np.array([[1000, 5, 1, 0, 0]])  # ค่าตัวอย่างที่ต้องปรับ
    prediction = model.predict(features)[0]
    return "unsafe" if prediction == 1 else "safe"

# ✅ API เช็ค URL จากทุกแหล่งข้อมูล
@app.post("/check_url/")
async def check_url(data: URLInput):
    """ ตรวจสอบ URL จากทุกแหล่งข้อมูล """
    domain_age = check_domain_age(data.url)

    results = {
        "Domain Age (days)": domain_age,
        "ML Model": check_ml_model(data.url),
        "OpenPhish": check_openphish(data.url),
        "PhishTank": check_phishtank(data.url),
        "Google Safe Browsing": check_google_safe_browsing(data.url),
        "URLhaus": check_urlhaus(data.url),
        "VirusTotal": check_virustotal(data.url),
    }

    # ถ้า URL อยู่ในฐานข้อมูลฟิชชิ่งหรือถูกพยากรณ์ว่า phishing → unsafe
    if "unsafe" in results.values():
        final_result = "unsafe"
    else:
        final_result = "safe"

    return {"url": data.url, "result": final_result, "details": results}
