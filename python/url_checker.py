# url_checker.py
import os, re, ssl, socket, math, tldextract, whois, requests, csv
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs

# ---------------------------
# Helpers / constants
# ---------------------------
SUSPICIOUS_TLDS = {
    "cn","tk","ml","xyz","buzz","shop","cf","net","ga"
}

SHORTENERS = [
    "bit.ly","tinyurl.com","goo.gl","t.co","ow.ly","is.gd","cutt.ly"
]

PHISH_WORDS = [
    "login","signin","verify","update","account","secure","bank","wallet","reset"
]

FILE_EXT_RE = re.compile(r"\.(exe|zip|rar|7z|tar|gz|scr|bat|cmd|js|vbs|ps1|dll|apk|jar|msi|iso|php|asp|aspx|jsp|cgi|pl|sh|html?|pdf|docx?|xlsx?|pptx?)$", re.I)

# ---------------------------
# Basic utils
# ---------------------------
def normalize_url(url: str) -> str:
    url = (url or "").strip()
    parsed = urlparse(url)
    if not parsed.scheme:
        # เดาเป็น https ถ้าดูเหมือนโดเมนปกติ
        if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/|$)", url):
            url = "https://" + url
        else:
            url = "http://" + url
        parsed = urlparse(url)
    if not parsed.netloc:
        url = urljoin("http://", url)
    return url

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [float(s.count(c))/len(s) for c in set(s)]
    return -sum(p*math.log(p, 2) for p in probs)

# ---------------------------
# URL feature extractor
# ---------------------------
def extract_url_features(url: str) -> dict:
    parsed = urlparse(url)
    host = parsed.netloc or ""
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()

    if not host:
        return {}

    length_url = len(url)
    length_hostname = len(host)
    host_only = host.split(":")[0]

    ip = 1 if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host_only) else 0
    punycode = 1 if host_only.startswith("xn--") else 0

    ratio_digits_url = sum(ch.isdigit() for ch in url) / max(len(url), 1)
    ratio_digits_host = sum(ch.isdigit() for ch in host_only) / max(len(host_only), 1)

    ex = tldextract.extract(url)
    tld = (ex.suffix or "").lower()
    domain_main = (ex.domain or "").lower()

    # subdomain count
    parts = host_only.split(".")
    if tld and len(parts) >= 2:
        sub_parts = parts[:-2]
    else:
        sub_parts = parts[:-1]
    nb_subdomains = len([p for p in sub_parts if p])

    tld_in_path = 1 if tld and tld in path else 0
    tld_in_subdomain = int(any(tld and (tld in s.lower()) for s in sub_parts))

    random_domain = 1 if any(c.isdigit() for c in domain_main) and len(set(domain_main)) < 6 else 0
    shortening_service = int(any(s in host_only.lower() for s in SHORTENERS))

    path_extension = 1 if (FILE_EXT_RE.search(path) or (FILE_EXT_RE.search(query or "") is not None)) else 0
    prefix_suffix = 1 if "-" in domain_main else 0
    phish_hints = int(any(w in (path + "?" + query) for w in PHISH_WORDS))

    url_entropy = shannon_entropy(url)
    uses_https = 1 if parsed.scheme == "https" else 0
    is_http = 1 if parsed.scheme == "http" else 0
    num_query_params = len(parse_qs(parsed.query))
    has_at_symbol = 1 if "@" in url else 0

    return {
        "length_url": length_url,
        "length_hostname": length_hostname,
        "ip": ip,
        "punycode": punycode,
        "ratio_digits_url": ratio_digits_url,
        "ratio_digits_host": ratio_digits_host,
        "nb_subdomains": nb_subdomains,
        "tld_in_path": tld_in_path,
        "tld_in_subdomain": tld_in_subdomain,
        "random_domain": random_domain,
        "shortening_service": shortening_service,
        "path_extension": path_extension,
        "prefix_suffix": prefix_suffix,
        "phish_hints": phish_hints,
        "url_entropy": url_entropy,
        "uses_https": uses_https,
        "is_http": is_http,
        "num_query_params": num_query_params,
        "has_at_symbol": has_at_symbol,
        # เพิ่มตรงนี้ให้ app ใช้ต่อ
        "tld": tld,
        "tld_risk": 1 if tld in SUSPICIOUS_TLDS else 0,
    }

# ---------------------------
# SSL / certificate
# ---------------------------
def _dnsname_match(hostname: str, pattern: str) -> bool:
    """
    Wildcard match แบบมาตรฐาน: *.example.com ครอบ a.example.com แต่ไม่ใช่ example.com
    """
    hostname = (hostname or "").lower()
    pattern = (pattern or "").lower()
    if not hostname or not pattern:
        return False
    if pattern == hostname:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        if hostname.endswith(suffix) and hostname.count(".") > suffix.count("."):
            return True
    return False

def check_ssl_certificate(domain: str) -> dict:
    feats = {
        "ssl_valid": 0,
        "cert_days_left": -1,
        "cert_issuer": "",
        "san_count": 0,
        "cert_cn_matches_domain": 0,
        # เสริม: ใช้ตรวจ hostname กับ SAN/CN ตามจริง
        "cert_hostname_ok": 0,
    }
    try:
        host = (domain or "").split(":")[0]
        if not host:
            return feats

        with socket.create_connection((host, 443), timeout=5) as sock:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return feats

                feats["ssl_valid"] = 1

                # notAfter -> days left
                not_after = cert.get("notAfter")
                if not_after:
                    try:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        feats["cert_days_left"] = max((exp - datetime.utcnow()).days, 0)
                    except Exception:
                        pass

                # issuer CN (optional)
                try:
                    issuer = dict(x for tup in cert.get("issuer", []) for x in tup)
                    feats["cert_issuer"] = issuer.get("commonName", "") or ""
                except Exception:
                    pass

                # SAN list
                sans = cert.get("subjectAltName", [])
                feats["san_count"] = len(sans)
                san_dns = [v for (k, v) in sans if k.lower() == "dns"]

                # Subject CN
                cn_items = []
                try:
                    subject = cert.get("subject", [])
                    cn_items = [v for tup in subject for (k, v) in tup if k == "commonName"]
                except Exception:
                    pass
                cn = (cn_items[0] if cn_items else "").lower()

                # legacy: CN contains host or vice versa
                if cn:
                    feats["cert_cn_matches_domain"] = 1 if (host.lower() in cn or cn in host.lower()) else 0

                # strict: match host against SAN / CN by wildcard rule
                ok = False
                for pat in san_dns:
                    if pat and _dnsname_match(host, pat):
                        ok = True
                        break
                if not ok and cn:
                    ok = _dnsname_match(host, cn)
                feats["cert_hostname_ok"] = 1 if ok else 0

    except Exception:
        return feats

    return feats

# ---------------------------
# WHOIS
# ---------------------------
def get_whois_features(domain: str) -> dict:
    feats = {
        "domain_age_days": -1,
        "days_since_update": -1,
        "has_whois_privacy": 0,
        "registrar": ""
    }
    try:
        dom = (domain or "").split(":")[0]
        if not dom:
            return feats
        w = whois.whois(dom)

        c = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        u = w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date

        if isinstance(c, datetime):
            feats["domain_age_days"] = (datetime.now() - c).days
        if isinstance(u, datetime):
            feats["days_since_update"] = (datetime.now() - u).days

        feats["registrar"] = (w.registrar or "") if hasattr(w, "registrar") else ""

        # privacy flags
        val = (str(getattr(w, "org", "") or "") + str(getattr(w, "name", "") or "")).lower()
        feats["has_whois_privacy"] = 1 if any(k in val for k in ["privacy", "redacted", "whoisguard"]) else 0
    except Exception:
        pass
    return feats

# ---------------------------
# HTTP features (requests)
# ---------------------------
def get_http_features(url: str) -> dict:
    feats = {
        "redirect_chain_len": 0,
        "final_domain_differs": 0,
        "has_security_headers": 0,
        "server_header": ""
    }
    try:
        r = requests.get(url, timeout=8, allow_redirects=True)
        feats["redirect_chain_len"] = len(r.history)

        start_host = urlparse(url).hostname or ""
        final_host = urlparse(r.url).hostname or ""
        feats["final_domain_differs"] = 1 if (start_host and final_host and (start_host.lower() != final_host.lower())) else 0

        h = {k.lower(): v for k, v in r.headers.items()}
        if "strict-transport-security" in h or "content-security-policy" in h or "x-frame-options" in h:
            feats["has_security_headers"] = 1
        feats["server_header"] = r.headers.get("Server", "")
    except Exception:
        pass
    return feats

# ---------------------------
# Lightweight typosquat flag
# ---------------------------
HOMOGLYPH_DIGIT = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t"})

def _looks_like_typosquat(domain_main: str, punycode=0, nb_subdomains=0) -> bool:
    risky_chars = any(c.isdigit() for c in domain_main) or "-" in domain_main
    risky_puny = (punycode == 1)
    risky_sub = nb_subdomains >= 3
    normalized = (domain_main or "").translate(HOMOGLYPH_DIGIT)
    risky_norm = (normalized != domain_main and len(domain_main) >= 5)
    return bool(risky_chars or risky_puny or risky_sub or risky_norm)

# ---------------------------
# Main aggregator
# ---------------------------
def analyze_full_url(raw_url: str) -> dict:
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    domain = parsed.netloc or ""

    url_feats = extract_url_features(url)
    ssl_feats = check_ssl_certificate(domain)
    whois_feats = get_whois_features(domain)
    http_feats = get_http_features(url)

    # typosquat candidate (แบบเบา ๆ)
    ex = tldextract.extract(url)
    domain_main = (ex.domain or "").lower()
    typosquat_flag = _looks_like_typosquat(
        domain_main=domain_main,
        punycode=url_feats.get("punycode", 0),
        nb_subdomains=url_feats.get("nb_subdomains", 0)
    )

    # ค่าเพิ่มเติม/ดีฟอลต์สำหรับความเข้ากันได้กับ app.py
    extra_defaults = {
        "typosquat_candidate": 1 if typosquat_flag else 0,
        "typosquat_score_max": 0,
        "typosquat_score_mean": 0,
        "typosquat_distance": 0,
        # fields ด้าน XAI/label
        "label": 0,
    }

    result = {
        "url": url,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        **url_feats,
        **ssl_feats,
        **whois_feats,
        **http_feats,
        **extra_defaults,
    }

    # เติมค่า default ที่ app คาดหวัง (ป้องกัน None)
    if result.get("domain_age_days") is None:
        result["domain_age_days"] = -1
    for k in ("cert_days_left", "san_count"):
        if result.get(k) is None:
            result[k] = 0

    return result

__all__ = ["normalize_url", "analyze_full_url"]
