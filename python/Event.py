import requests
import json
import time
import base64
import hashlib
import pathlib
import os
import ssl
import socket
import re
import atexit
import tldextract
import string
import math
import whois
import ssl, socket
import re, math, tldextract
import csv
from urllib.parse import urlparse, parse_qs
from urllib.parse import urlparse, urlunparse
from datetime import datetime
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from urllib.parse import parse_qs




# ✅ ตั้งค่า WebDriver
chrome_options = Options()
chrome_options.add_argument("--headless=new")   # หรือเอาออกถ้าอยากเห็นหน้าจอ
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--disable-dev-shm-usage")

chrome_options.set_capability("goog:loggingPrefs", {"performance": "ALL"})


"""service = Service("/usr/bin/chromedriver")"""
driver = webdriver.Chrome(options=chrome_options)

# ✅ API Keys
GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyAOY26ThIRKUvkQeIrGUKjTmLDvCob10DY"
VIRUSTOTAL_API_KEY = "c64e4f214217d6933a538f881882fdb09cf11ea5691ba0588a24dda69b891a0a"

'''
# ✅ VirusTotal API
def check_virustotal(url):
        """ ตรวจสอบ URL ผ่าน VirusTotal API """
        api_url = f"https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
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

    # ✅ Google Safe Browsing API
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
'''
    # ✅ อัปเดตฐานข้อมูลอัตโนมัติ
def update_databases():
        sources = {
            "openphish": "https://openphish.com/feed.txt",
            "urlhaus": "https://urlhaus.abuse.ch/downloads/json/"
        }
        for name, url in sources.items():
            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                data = response.text if name == "openphish" else response.json()
                with open(f"database/{name}.json", "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
                print(f"✅ {name.capitalize()} database updated.")
            except Exception as e:
                print(f"❌ Error updating {name}: {e}")

def check_ssl_certificate(domain):
    """ ตรวจสอบ SSL Certificate ของโดเมน """
    try:
        host, sep, port = domain.partition(":")
        port = int(port) if sep else 443  # ถ้าไม่มี port ให้ใช้ 443

        if port != 443:
            print(f"⚠️ Skipping SSL check for non-443 port: {host}:{port}")
            return None

        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                print(f"✅ SSL Certificate is valid for domain: {host}")
                return cert
    except Exception as e:
        print(f"❌ SSL Certificate error for domain {domain}: {e}")
        return None

def check_domain_age(domain):
    try:
        # 🔎 ถ้ามีพอร์ต เช่น 103.130.212.99:8080 → ตัดพอร์ตออกก่อน
        domain = domain.split(":")[0]

        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):  # บางโดเมนคืน list
            creation_date = creation_date[0]

        if creation_date is None:
            print("⚠️ Cannot find domain creation date.")
            return None

        age_days = (datetime.now() - creation_date).days
        print(f"📅 Domain creation date: {creation_date} (Age: {age_days} days)")
        return age_days

    except Exception as e:
        print(f"❌ Error checking domain age for {domain}: {e}")
        return None

    # ✅ นิยาม pattern เพื่อตรวจจับอักขระพิเศษ
special_characters_pattern = re.compile(r"[-._~:/?#@!$&'()*+,;=%]")

# ✅ ฟังก์ชันดึงฟีเจอร์จาก URL

# ✅ list ของนามสกุลไฟล์ที่เสี่ยง
SUSPICIOUS_EXTENSIONS = [
    "exe", "zip", "rar", "7z", "tar", "gz",
    "scr", "bat", "cmd", "js", "vbs", "ps1",
    "dll", "apk", "ipa", "jar", "msi", "iso",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf",
    "php", "asp", "aspx", "jsp", "cgi", "pl", "sh", "html", "htm"
]

# ✅ จัดกลุ่มไฟล์
FILE_GROUPS = {
    "executable": ["exe", "dll", "apk", "jar", "msi", "scr", "bat", "cmd", "ps1"],
    "archive": ["zip", "rar", "7z", "tar", "gz", "iso"],
    "script": ["js", "vbs", "php", "asp", "aspx", "jsp", "cgi", "pl", "sh"],
    "document": ["doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "html", "htm"]
}

def add_similarity_features(df):
    df["typosquat_score_max"] = df["similar_to"].apply(
        lambda x: max([d["score"] for d in x], default=0)
    )
    df["typosquat_score_mean"] = df["similar_to"].apply(
        lambda x: np.mean([d["score"] for d in x]) if x else 0
    )
    df["typosquat_distance"] = 100 - df["typosquat_score_max"]
    return df


def get_file_category(ext):
    for category, exts in FILE_GROUPS.items():
        if ext in exts:
            return category
    return "other"

SUSPICIOUS_TLDS = {
    "cn", "tk", "ml", "xyz", "buzz",
    "shop", "cf", "net", "ga"
}

def extract_url_features(url):
    # ✅ ถ้าไม่มี http:// หรือ https:// ให้เติม http://
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.netloc
    path = parsed.path.lower()
    query = parsed.query.lower()
    tld = tldextract.extract(url).suffix.lower()

    length_url = len(url)
    length_hostname = len(hostname)
    host_only = hostname.split(":")[0]  # 🔧 ตัดพอร์ตออก (ถ้ามี)
    ip_match = bool(re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", host_only))
    punycode = 1 if hostname.startswith("xn--") else 0
    ratio_digits_url = sum(c.isdigit() for c in url) / len(url)
    ratio_digits_host = sum(c.isdigit() for c in hostname) / len(hostname) if hostname else 0
    subdomain_parts = hostname.split('.')[:-2]
    nb_subdomains = len(subdomain_parts)
    tld_in_path = 1 if tld in path else 0
    tld_in_subdomain = int(any(tld in s for s in subdomain_parts))
    domain_main = tldextract.extract(url).domain
    random_domain = 1 if any(c.isdigit() for c in domain_main) and len(set(domain_main)) < 6 else 0
    shortening_services = ["bit.ly", "tinyurl.com", "goo.gl", "t.co"]
    shortening_service = 1 if any(s in hostname for s in shortening_services) else 0
    prefix_suffix = 1 if "-" in domain_main else 0
    hints = ["login", "verify", "update", "account", "secure"]
    phish_hints = 1 if any(hint in path.lower() for hint in hints) else 0
    tld_risk = 1 if tld in SUSPICIOUS_TLDS else 0

    # ✅ ตรวจจับนามสกุลไฟล์
    file_extension = None
    for ext in SUSPICIOUS_EXTENSIONS:
        if path.endswith("." + ext) or f".{ext}" in query:
            file_extension = ext
            break

    # ✅ เพิ่มฟีเจอร์ใหม่ 4 ตัว
    entropy = shannon_entropy(url)
    is_https = 1 if parsed.scheme == "https" else 0
    is_http = 1 if parsed.scheme == "http" else 0
    num_query_params = len(parse_qs(parsed.query))
    has_at_symbol = 1 if "@" in url else 0

    return {
    "length_url": length_url,
    "length_hostname": length_hostname,
    "ip": int(ip_match),
    "punycode": punycode,
    "ratio_digits_url": ratio_digits_url,
    "ratio_digits_host": ratio_digits_host,
    "nb_subdomains": nb_subdomains,
    "tld_in_path": tld_in_path,
    "tld_in_subdomain": tld_in_subdomain,
    "random_domain": random_domain,
    "shortening_service": shortening_service,
    "prefix_suffix": prefix_suffix,
    "phish_hints": phish_hints,
    "url_entropy": entropy,
    "uses_https": is_https,
    "is_http": is_http,
    "num_query_params": num_query_params,
    "has_at_symbol": has_at_symbol,
    "path_extension": 1 if file_extension else 0,   # เดิม
    "file_extension": file_extension or "none",     # 🆕 ชนิดไฟล์
    "file_category": get_file_category(file_extension) if file_extension else "none",  # 🆕 กลุ่มไฟล์
    "tld": tld,                # 🆕 เก็บค่า TLD ตรง ๆ
    "tld_risk": tld_risk       # 🆕 ฟีเจอร์ TLD เสี่ยง
}

def shannon_entropy(url):
    prob = [float(url.count(c)) / len(url) for c in set(url)]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def analyze_url(url):
        """ วิเคราะห์ข้อมูลพื้นฐานของ URL """
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        domain_length = len(domain)

        # ✅ ตรวจจับตัวอักษรพิเศษ
        special_chars = special_characters_pattern.findall(url)
        special_chars_count = len(special_chars)

        # ✅ ตรวจสอบคำที่น่าสงสัยใน URL
        suspicious_keywords = ["login", "secure", "verify", "bank", "account", "password", "update", "confirm"]
        found_suspicious_keywords = [word for word in suspicious_keywords if word in url.lower()]
        contains_suspicious_keywords = bool(found_suspicious_keywords)

        analysis_result = {
            "url_length": len(url),
            "domain_length": domain_length,
            "special_chars_count": special_chars_count,
            "special_chars": special_chars,  # ✅ แสดงอักขระพิเศษที่พบ
            "contains_suspicious_keywords": contains_suspicious_keywords,
            "suspicious_keywords_found": found_suspicious_keywords  # ✅ แสดงคำที่น่าสงสัย
        }

        # ✅ แสดงรายละเอียดแบบอ่านง่าย
        print("\n🔍 **URL Analysis Details**")
        print(f"🔗 URL: {url}")
        print(f"📏 URL Length: {analysis_result['url_length']} characters")
        print(f"🏠 Domain: {domain} (Length: {analysis_result['domain_length']} characters)")
        print(f"🔣 Special Characters: {analysis_result['special_chars_count']} found ({', '.join(analysis_result['special_chars'])})" if analysis_result['special_chars_count'] > 0 else "🔣 No special characters detected.")
        
        if analysis_result["contains_suspicious_keywords"]:
            print(f"⚠️ Suspicious Keywords Detected: {', '.join(analysis_result['suspicious_keywords_found'])}")
        else:
            print("✅ No suspicious keywords found.")

        return analysis_result

def detect_cookie_popup():
        """ ตรวจจับ Cookie Consent Popup โดยใช้หลายวิธี """
        try:
            print("🔎 Checking for Cookie Consent Popup...")

            # ✅ ตรวจจับ <mat-dialog-container> (Angular Material Dialog)
            popup = WebDriverWait(driver, 5).until(
                EC.presence_of_element_located((By.XPATH, "//mat-dialog-container | //div[contains(@class, 'cookie')] | //div[contains(text(), 'Your Privacy Matters')]"))
            )
            print("✅ Cookie Consent Popup detected!")

            return True  # พบ Popup
        except Exception:
            print("⚠️ No Cookie Consent Popup detected.")
            return False  # ไม่พบ Popup

def extract_redirect_chain_from_logs(perf_logs):
    """
    คืนค่า:
      chain: list[ {from, to, status, location_header} ... ]
      last_seen_url: URL ล่าสุดที่พบใน log
    ใช้อีเวนต์ Network.requestWillBeSent และฟิลด์ redirectResponse
    """
    import json
    chain = []
    last_seen_url = None

    for entry in perf_logs:
        try:
            msg = json.loads(entry["message"])["message"]
        except Exception:
            continue

        if msg.get("method") == "Network.requestWillBeSent":
            params = msg.get("params", {})
            req = params.get("request", {})
            if req and "url" in req:
                last_seen_url = req["url"]

            # ถ้ามี redirectResponse แปลว่ามีรีไดเรกต์ hop ก่อนหน้า
            if "redirectResponse" in params:
                rr = params["redirectResponse"]
                chain.append({
                    "from": rr.get("url"),
                    "to": req.get("url"),
                    "status": rr.get("status"),
                    "location_header": (rr.get("headers", {}) or {}).get("location")
                })

    # ลบรายการซ้ำแบบง่ายๆ
    dedup = []
    seen = set()
    for hop in chain:
        key = (hop["from"], hop["to"], hop["status"])
        if key not in seen:
            seen.add(key)
            dedup.append(hop)

    return dedup, last_seen_url

        
# ✅ รวมการวิเคราะห์ URL

def get_whois_features(domain):
    feats = {
        "domain_age_days": -1,
        "days_since_update": -1,
        "has_whois_privacy": -1,
        "registrar": ""
    }
    try:
        w = whois.whois(domain.split(":")[0])
        # creation
        c = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        u = w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date
        if isinstance(c, datetime):
            feats["domain_age_days"] = (datetime.now() - c).days
        if isinstance(u, datetime):
            feats["days_since_update"] = (datetime.now() - u).days
        feats["registrar"] = w.registrar or ""
        # privacy
        val = str(w.get("org") or "") + str(w.get("name") or "")
        feats["has_whois_privacy"] = 1 if any(k in val.lower() for k in ["privacy","redacted","whoisguard"]) else 0
    except Exception:
        pass
    return feats

def get_http_features(url):
    feats = {
        "redirect_chain_len": -1,
        "final_domain_differs": -1,
        "has_security_headers": 0,
        "server_header": ""
    }
    try:
        r = requests.get(url, timeout=8, allow_redirects=True)
        feats["redirect_chain_len"] = len(r.history)
        feats["final_domain_differs"] = 1 if urlparse(url).hostname != urlparse(r.url).hostname else 0
        h = {k.lower(): v for k,v in r.headers.items()}
        if "strict-transport-security" in h or "content-security-policy" in h or "x-frame-options" in h:
            feats["has_security_headers"] = 1
        feats["server_header"] = r.headers.get("Server","")
    except Exception:
        pass
    return feats

def get_tls_features(domain):
    feats = {
        "ssl_valid": 0,
        "cert_days_left": -1,
        "cert_issuer": "",
        "san_count": -1,
        "cert_cn_matches_domain": -1
    }
    try:
        host, sep, port = domain.partition(":")
        port = int(port) if sep else 443
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        feats["ssl_valid"] = 1
        issuer = dict(x for tup in cert.get("issuer", []) for x in tup)
        feats["cert_issuer"] = issuer.get("commonName", "")
        subject = dict(x for tup in cert.get("subject", []) for x in tup)
        feats["cert_cn_matches_domain"] = 1 if host in subject.get("commonName", "") else 0
        exp = datetime.strptime(cert["notAfter"], r"%b %d %H:%M:%S %Y %Z")
        feats["cert_days_left"] = (exp - datetime.utcnow()).days
        sans = [v for (k, v) in cert.get("subjectAltName", []) if k == "DNS"]
        feats["san_count"] = len(sans)
    except Exception:
        pass
    return feats

HOMOGLYPH_DIGIT = str.maketrans({"0":"o","1":"l","3":"e","5":"s","7":"t"})

def _looks_like_typosquat(domain_main, punycode=0, nb_subdomains=0):
    # 1) มีตัวเลขเยอะ/มี - ในชื่อ
    risky_chars = any(c.isdigit() for c in domain_main) or "-" in domain_main
    # 2) punycode
    risky_puny = (punycode == 1)
    # 3) subdomain เยอะผิดปกติ (เช่น 3+)
    risky_sub = nb_subdomains >= 3
    # 4) แทนตัวเลขเป็นตัวอักษรแล้วคล้ายเดิมมาก (g00gle -> goolge/go0gle pattern)
    normalized = domain_main.translate(HOMOGLYPH_DIGIT)
    risky_norm = (normalized != domain_main and len(domain_main) >= 5)
    return risky_chars or risky_puny or risky_sub or risky_norm

def normalize_typos(domain: str) -> str:
    """แทนตัวเลขที่มักถูกใช้แทนอักษร เช่น g00gle -> google"""
    replacements = {
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "7": "t"
    }
    for k, v in replacements.items():
        domain = domain.replace(k, v)
    return domain

def normalize_url(u: str) -> str:
    u = (u or "").strip()
    if not u:
        return u
    if not u.startswith(("http://", "https://")):
        # ถ้าขึ้นต้นเป็นโดเมนปกติ แนะนำ https
        if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/|$)", u):
            return "https://" + u
        return "http://" + u
    return u

def analyze_full_url(url):
    url = normalize_url(url)  # <<< เพิ่ม normalize ที่นี่

    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # ----- ฟีเจอร์ย่อยเดิม -----
    features = extract_url_features(url)   # ใช้ url ที่ normalize แล้ว
    base_analysis = analyze_url(url)       # ใช้ url ที่ normalize แล้ว
    http_feats = get_http_features(url)    # ใช้ url ที่ normalize แล้ว
    whois_feats = get_whois_features(domain)
    tls_feats = get_tls_features(domain)

    # ----- รวมผลพื้นฐาน -----
    result = {
        "url": url,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        **features,
        **base_analysis,
        **tls_feats,
        **whois_feats,
        **http_feats,
    }
    if result.get("domain_age_days") is None:
        result["domain_age_days"] = -1

    # ----- เงื่อนไขตรวจ typosquat -----
    ex = tldextract.extract(url)
    registered_domain = f"{ex.domain}.{ex.suffix}".lower() if ex.suffix else ex.domain.lower()
    domain_main = ex.domain.lower()

    typosquat_flag = _looks_like_typosquat(
        domain_main=domain_main,
        punycode=features.get("punycode", 0),
        nb_subdomains=features.get("nb_subdomains", 0)
    )

    similar_hits = []
    if typosquat_flag:
        normalized_domain = normalize_typos(registered_domain)
        legit = _load_legit_domains()
        if normalized_domain in legit:
            similar_hits = [(normalized_domain, 100)]

    result["typosquat_candidate"] = int(bool(typosquat_flag))
    result["similar_to"] = [{"domain": d, "score": s} for d, s in similar_hits]

    if result["similar_to"]:
        result["typo_domain"] = registered_domain
        result["real_domain"] = result["similar_to"][0]["domain"]
        print(f"🔗 Similar legit domain detected: {result['similar_to']}")
        print(f"⚠️ Typosquat mapping: {result['typo_domain']} → {result['real_domain']}")

    result["label"] = 0
    return result


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_DIR = os.path.join(BASE_DIR, "database")

# ให้แน่ใจว่ามีโฟลเดอร์ database
os.makedirs(DATABASE_DIR, exist_ok=True)

# input/output
input_file = os.path.join(BASE_DIR, "legitimate_shuffle_urls.txt")
output_file = os.path.join(DATABASE_DIR, "legitimate_urls.json")

results = []

# ✅ โหลดข้อมูลเก่าใน data.json ถ้ามี
if os.path.exists(output_file):
    with open(output_file, "r", encoding="utf-8") as f:
        try:
            existing_data = json.load(f)
        except json.JSONDecodeError:
            existing_data = []
else:
    existing_data = []

# canonical helper (ใช้เปรียบเทียบ URL โดยไม่สนใจ scheme / trailing slash)
def canonical_key(u: str) -> str:
    if not u:
        return u
    s = u.strip()
    # เติม scheme เพื่อ parse ให้ถูก ถ้ามันขาด
    if not s.startswith(("http://", "https://")):
        s = "http://" + s
    p = urlparse(s)
    host = p.netloc.lower()
    # ถ้าต้องการให้ www.example == example ให้ uncomment บรรทัดต่อไปนี้
    # if host.startswith("www."): host = host[4:]
    path = p.path.rstrip("/") or ""   # เอา trailing slash ออก (ถ้าผลลัพธ์เป็น "/" ให้เป็น "")
    if p.query:
        return host + path + "?" + p.query
    return host + path

# ✅ สร้าง Set ของ URL ที่มีอยู่แล้ว (ใช้ canonical_key)
existing_urls = set()
for entry in existing_data:
    u = entry.get("url")
    if u:
        existing_urls.add(canonical_key(u))


# 🔹 Cache สำหรับโหลดโดเมน legit
_LEGIT_CACHE = None

LEGIT_TOP_PATH = os.path.join(DATABASE_DIR, "top1m.csv")  # หรือไฟล์ CSV ของ legit domains

def _load_legit_domains(limit=100000):
    """โหลด top1m เฉพาะคอลัมน์โดเมน (คอลัมน์ที่ 2) และแคชไว้"""
    global _LEGIT_CACHE
    if _LEGIT_CACHE is not None:
        return _LEGIT_CACHE

    legit = []
    try:
        with open(LEGIT_TOP_PATH, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    domain = row[1].strip().lower()
                    if domain:
                        legit.append(domain)
                        if limit and len(legit) >= limit:
                            break
    except Exception as e:
        print(f"⚠️ Cannot load {LEGIT_TOP_PATH}: {e}")
        legit = []

    _LEGIT_CACHE = legit
    print(f"✅ Loaded {len(_LEGIT_CACHE)} legit domains (cached)")
    return _LEGIT_CACHE


# ตั้งค่าวิธีเก็บ: "omit", "meta", "file", หรือ "truncate"
NETWORK_STORE_MODE = "meta"   # <-- เปลี่ยนเป็น "file" ถ้าต้องการเซฟเป็นไฟล์จริง ๆ
NETWORK_MAX_KEEP = 500        # ถ้าใช้ truncate จะเก็บสูงสุดกี่ตัวอักษร

# โฟลเดอร์สำหรับเก็บไฟล์ภาพจาก data: URIs (ถ้าใช้ mode "file")
NETWORK_FILES_DIR = os.path.join(DATABASE_DIR, "network_files")
os.makedirs(NETWORK_FILES_DIR, exist_ok=True)

def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def process_network_url(url):
    """
    รับค่า url ที่ได้จาก performance logs และคืนค่า 'sanitized' เพื่อเก็บใน JSON:
    - หาก mode == "omit": คืน None
    - หาก mode == "meta": คืน dict {type: 'data'|'blob'|'http', mime, size, sha256, truncated, sample}
    - หาก mode == "file": ถ้า data: decode -> เซฟไฟล์ -> คืน pth + meta; ถ้า blob: คืน placeholder
    - หาก mode == "truncate": เก็บ prefix NETWORK_MAX_KEEP
    """
    if not url:
        return None

    # data URI (base64 encoded)
    if url.startswith("data:"):
        # ตัวอย่าง header: data:image/gif;base64,R0lG...
        try:
            header, b64 = url.split(",", 1)
        except ValueError:
            return {"type": "data", "error": "malformed"}

        mime = header.split(";")[0].split(":", 1)[1] if ";" in header else header.split(":", 1)[1]
        is_base64 = "base64" in header

        if not is_base64:
            # ถ้า data URI ไม่ใช่ base64 (rare) ให้ตัดเก็บ sample หรือ omit
            if NETWORK_STORE_MODE == "omit":
                return None
            elif NETWORK_STORE_MODE == "truncate":
                return {"type": "data", "mime": mime, "sample": url[:NETWORK_MAX_KEEP], "truncated": len(url) > NETWORK_MAX_KEEP}
            else:
                return {"type": "data", "mime": mime, "sample": url[:NETWORK_MAX_KEEP], "truncated": len(url) > NETWORK_MAX_KEEP}

        try:
            binary = base64.b64decode(b64)
        except Exception:
            return {"type": "data", "mime": mime, "error": "base64_decode_failed"}

        size = len(binary)
        sha256 = _sha256_bytes(binary)

        if NETWORK_STORE_MODE == "omit":
            return {"type": "data", "mime": mime, "size": size, "sha256": sha256}

        elif NETWORK_STORE_MODE == "truncate":
            sample = url[:NETWORK_MAX_KEEP]
            return {"type": "data", "mime": mime, "size": size, "sha256": sha256, "sample": sample, "truncated": True if len(url) > NETWORK_MAX_KEEP else False}

        elif NETWORK_STORE_MODE == "meta":
            return {"type": "data", "mime": mime, "size": size, "sha256": sha256}

        elif NETWORK_STORE_MODE == "file":
            # สร้างชื่อไฟล์จาก hash+extension
            ext = ""
            if "/" in mime:
                ext = "." + mime.split("/")[-1]
            fname = f"network_{sha256}{ext}"
            p = pathlib.Path(NETWORK_FILES_DIR) / fname
            # ถ้ายังไม่มีไฟล์ ให้เซฟ
            if not p.exists():
                try:
                    p.write_bytes(binary)
                except Exception as e:
                    return {"type": "data", "mime": mime, "size": size, "sha256": sha256, "error": f"write_failed:{e}"}
            return {"type": "data", "file": str(p), "mime": mime, "size": size, "sha256": sha256}

    # blob: URL (เบราว์เซอร์ object URL) — มักเข้าถึงไม่ได้จากภายนอก
    if url.startswith("blob:"):
        if NETWORK_STORE_MODE in ("omit", "meta", "truncate"):
            out = {"type": "blob", "value": url if NETWORK_STORE_MODE == "truncate" and len(url) <= NETWORK_MAX_KEEP else None}
            if NETWORK_STORE_MODE == "meta":
                out.update({"note": "blob_url_not_resolvable_outside_browser"})
            if NETWORK_STORE_MODE == "truncate":
                out["truncated"] = len(url) > NETWORK_MAX_KEEP
                if len(url) > NETWORK_MAX_KEEP:
                    out["sample"] = url[:NETWORK_MAX_KEEP]
            return out
        elif NETWORK_STORE_MODE == "file":
            # ไม่สามารถ decode blob: ได้จาก server — เก็บเป็น meta แทน
            return {"type": "blob", "note": "cannot_save_blob_url_server_side", "value": url[:NETWORK_MAX_KEEP], "truncated": len(url) > NETWORK_MAX_KEEP}

    # กรณี URL ปกติ (http/https) — หากยาวมาก ให้ truncate หรือเก็บเต็มแล้วแต่ต้องการ
    if url.startswith("http://") or url.startswith("https://"):
        if NETWORK_STORE_MODE == "truncate" and len(url) > NETWORK_MAX_KEEP:
            return {"type": "http", "sample": url[:NETWORK_MAX_KEEP], "truncated": True}
        else:
            return {"type": "http", "value": url}

    # ดีฟอลต์
    return {"type": "unknown", "value": url if len(url) <= NETWORK_MAX_KEEP else url[:NETWORK_MAX_KEEP], "truncated": len(url) > NETWORK_MAX_KEEP}

def safe_preview(data, max_chars=1000):
    s = json.dumps(data, indent=2, ensure_ascii=False)
    if len(s) > max_chars:
        return s[:max_chars] + "\n... (truncated preview)"
    return s


def _nearest_legit_domains(qdomain, top_k=3, min_score=85):
    """
    คืนรายการโดเมนจริงที่คล้าย qdomain มากที่สุด
    - ถ้ามี rapidfuzz ใช้ fuzz.ratio (0..100)
    - ถ้าไม่มี ใช้ difflib.get_close_matches
    """
    legit = _load_legit_domains()

    if not legit:
        return []

    q = qdomain.lower()

    if _USE_RAPIDFUZZ:
        matches = process.extract(q, legit, scorer=fuzz.ratio, limit=top_k)
        # matches: [(domain, score, index), ...]
        return [(d, int(s)) for d, s, _ in matches if s >= min_score]
    else:
        # difflib ให้ค่าคล้ายแบบ 0..1
        candidates = difflib.get_close_matches(q, legit, n=top_k, cutoff=min_score/100.0)
        # ประมาณคะแนนจาก difflib.SequenceMatcher
        out = []
        for d in candidates:
            s = int(difflib.SequenceMatcher(None, q, d).ratio() * 100)
            if s >= min_score:
                out.append((d, s))
        return out
    
try:
    if os.path.exists(input_file):
        with open(input_file, "r", encoding="utf-8") as f:
            raw_urls = [line.strip() for line in f if line.strip()]

        for raw_url in raw_urls:
            key = canonical_key(raw_url)

            if key in existing_urls:
                print(f"⏭️ Skipping already analyzed URL: {raw_url}  (canonical: {key})")
                continue

            # เติม scheme ถ้าจำเป็น เพื่อส่งให้ analyze/selenium
            url_for_scan = raw_url.strip()
            if not url_for_scan.startswith(("http://", "https://")):
                url_for_scan = "http://" + url_for_scan

            print(f"\n🔍 Processing URL: {raw_url}  -> scanning as: {url_for_scan}")

            result_entry = analyze_full_url(url_for_scan)
            print("✅ Analysis Result:", json.dumps(result_entry, indent=2))

            # Selenium / performance log
            try:
                driver.get(url_for_scan)
                time.sleep(1.5)
                logs = driver.get_log("performance")
                chain, last_seen = extract_redirect_chain_from_logs(logs)

                result_entry["selenium_current_url"] = driver.current_url
                result_entry["redirect_chain"] = chain
                result_entry["network_last_seen_url"] = process_network_url(last_seen)
            except Exception as e:
                print(f"⚠️ Selenium navigate error for {url_for_scan}: {e}")
                result_entry["selenium_current_url"] = None
                result_entry["redirect_chain"] = []
                result_entry["network_last_seen_url"] = None

            # normalize ค่า fallback
            if result_entry.get("ssl_valid") is None:
                result_entry["ssl_valid"] = 0
            if result_entry.get("domain_age_days") is None:
                result_entry["domain_age_days"] = -1

            # เก็บ URL ผลลัพธ์ (analyze_full_url คืนค่า url ที่ normalize แล้ว)
            result_entry["url"] = result_entry.get("url") or url_for_scan

            # เพิ่มลง existing_data และ update set canonical keys
            existing_data.append(result_entry)
            existing_urls.add(canonical_key(result_entry["url"]))

            # บันทึกทันที (ช่วยป้องกัน re-run เมื่อถูกหยุด)
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(existing_data, f, indent=4)

        print(f"💾 Saved {len(existing_data)} entries → {output_file}")
    else:
        print(f"❌ Input file not found: {input_file}")

except KeyboardInterrupt:
    print("\n🛑 Monitoring stopped by user.")
    # ✅ Save partial results before exit
    if existing_data:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(existing_data, f, indent=4)
        print(f"✅ Partial data saved successfully in {output_file} before exit.")

except Exception as e:
    print(f"❌ Error: {e}")

try:
    # ✅ ถ้ามีไฟล์ input เลือกบรรทัดแรกเป็นหน้าเริ่ม monitor
    if os.path.exists(input_file):
        with open(input_file, "r", encoding="utf-8") as f:
            first_line = next((l.strip() for l in f if l.strip()), None)
        if first_line:
            start_url = normalize_url(first_line)  # ต้องมีฟังก์ชัน normalize_url ตามที่ให้ไว้
            driver.get(start_url)
            print(f"🚀 Navigated to start URL for monitoring: {start_url}")

    time.sleep(3)

    # ✅ ตรวจจับ Cookie Consent Popup
    has_popup = detect_cookie_popup()

    # ✅ แสดงผล
    if has_popup:
        print("⚠️ Found Cookie Consent Popup")
    else:
        print("✅ Not Found Cookie Consent Popup")

    # ตั้งค่าเริ่มต้นก่อนเข้า loop (ให้มีค่าชัวร์)
    previous_url = driver.current_url
    previous_windows = driver.window_handles

    while True:
        current_url = driver.current_url  # ✅ ใช้ current_url เป็นตัวหลัก
        domain = urlparse(current_url).netloc
        print(f"🌐 Monitoring domain: {domain}")

        # เว้นจังหวะรอบตรวจ
        time.sleep(10)  # ✅ เช็คทุก 10 วินาที

        # ✅ ตรวจสอบ SSL และอายุโดเมน (เก็บไว้ใช้ซ้ำ)
        ssl_ok = check_ssl_certificate(domain) is not None
        domain_age = check_domain_age(domain)

        # ✅ ดึง Performance Logs เพื่อหา redirect chain
        try:
            logs = driver.get_log("performance")
            chain, last_seen = extract_redirect_chain_from_logs(logs)
        except Exception as e:
            print(f"⚠️ get_log(performance) failed: {e}")
            chain, last_seen = [], None

        # ✅ ตรวจสอบ Redirect (ต้องคำนวณก่อนเปลี่ยน previous_url)
        redirected = (current_url != previous_url)
        if redirected:
            print(f"🔄 Redirected to: {current_url}")
        else:
            print(f"✅ No redirect detected. Current URL: {current_url}")
        # อัปเดตหลังคำนวณ redirected เสร็จ
        previous_url = current_url

        # ✅ ตรวจจับ HTML Pop-up
        pop_up_found = False
        try:
            WebDriverWait(driver, 2).until(
                EC.presence_of_element_located((
                    By.XPATH,
                    "//*[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'sign in') "
                    "or contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'alert')]"
                ))
            )
            pop_up_found = True
            print("⚠️ HTML Pop-up detected.")
        except:
            print("✅ No HTML Pop-up detected.")

        # ✅ ตรวจจับ JavaScript Alert
        alert_text = None
        try:
            WebDriverWait(driver, 2).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            alert_text = alert.text
            print(f"⚠️ JavaScript Alert detected: {alert_text}")
            alert.accept()
        except:
            print("✅ No JavaScript Alert detected.")

        # ✅ ตรวจจับการเปิดหน้าต่าง/แท็บใหม่
        current_windows = driver.window_handles
        new_tabs = max(0, len(current_windows) - len(previous_windows))
        if new_tabs > 0:
            print(f"⚠️ New window/tab detected: {new_tabs} new tab(s) opened.")
        previous_windows = current_windows  # อัปเดตรายการหน้าต่าง

        # ✅ ใช้พาธที่ถูกต้องสำหรับ data.json
        file_path = output_file

        # ✅ ตรวจสอบว่ามี database/ หรือไม่ ถ้าไม่มีให้สร้าง
        if not os.path.exists("database"):
            os.makedirs("database")

        # ✅ โหลด data.json ถ้ามีอยู่แล้ว
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as file:
                try:
                    existing_data = json.load(file)  # ✅ โหลดข้อมูลเก่า
                except json.JSONDecodeError:
                    print("⚠️ JSON Decode Error: Creating a new empty file.")
                    existing_data = []
        else:
            existing_data = []

        # ✅ ข้อมูลใหม่ที่ต้องเพิ่ม (ใช้ current_url)
        result_data = {
            "url": current_url,  # ✅ ใช้ current_url แทนการกำหนด URL ซ้ำ
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

            # TLS/WHOIS
            "ssl_valid": ssl_ok,            # ✅ ถ้า SSL ใช้ได้ -> True
            "domain_age_days": domain_age,  # ✅ อาจเป็น None/ตัวเลข

            # เนื้อหา URL
            "special_chars_count": len(special_characters_pattern.findall(current_url)),

            # การนำทาง/พฤติกรรมหน้า
            "redirected": redirected,
            "popup_detected": pop_up_found,
            "javascript_alert_detected": alert_text,
            "new_tabs_opened": new_tabs,

            # 🆕 จาก Selenium Performance Log
            "selenium_current_url": driver.current_url,
            "redirect_chain": chain,            # [{from,to,status,location_header}, ...]
            "network_last_seen_url": last_seen, # URL ล่าสุดที่พบใน network logs
        }

        # ✅ อัปเดตข้อมูลถ้ามี URL นี้อยู่แล้ว
        found = False
        for index, entry in enumerate(existing_data):
            if entry.get("url") == current_url:
                existing_data[index] = result_data  # ✅ แทนที่ข้อมูลเก่าด้วยข้อมูลใหม่
                found = True
                break

        # ✅ ถ้าไม่พบ URL เดิม ให้เพิ่มเป็นข้อมูลใหม่
        if not found:
            existing_data.append(result_data)

        # ✅ บันทึกใหม่แบบ JSON ลิสต์
        print("📂 Data before saving (preview):")
        print(safe_preview(existing_data, max_chars=2000))
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(existing_data, file, indent=4)

        print(f"✅ Data saved successfully in {file_path}!")

        time.sleep(10)  # ✅ เช็คทุก 10 วินาที

except KeyboardInterrupt:
    print("\n🛑 Monitoring stopped by user.")
    # ✅ Save partial results before exit
    if results:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(existing_data, f, indent=4)
        print(f"✅ Partial data saved successfully in {output_file} before exit.")

except Exception as e:
    print(f"❌ An unexpected error occurred: {e}")

finally:
    try:
        driver.quit()
        print("🛑 WebDriver closed.")
    except Exception as e:
        print("⚠️ Error closing WebDriver:", e)

    
