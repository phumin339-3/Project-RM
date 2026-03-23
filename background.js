try {
  importScripts("vendor/ort.min.js");
} catch (e) {
  console.error("Failed to load vendor/ort.min.js", e);
}
// background.js — allowlist CSV + DNR block (domain/URL) + auto model check + interstitial + history
// + notifications + offscreen handshake + SAFE BACK TARGET + SMART BACK + welcome on install
// + USER ALLOWLIST (add/remove via popup)
// + FEEDBACK (add/list/clear + export handled in page)
// + MASTER ENABLE SWITCH (ON/OFF) wired to popup
// + SPA/fragment/soft-redirect auto-check + redirect-from logging
// + BYPASS-FIX: ยังตรวจ/บันทึกระหว่าง bypass แต่ไม่เด้งหน้าเตือน

/***** CONFIG *****/
// ===== FIRESTORE (feedback) =====
const FIRESTORE_FEEDBACK_URL =
  "https://firestore.googleapis.com/v1/projects/phishing-c9e6b/databases/(default)/documents/FirefoxExtension_Feedback";

const HISTORY_KEY = "check_history";
const HISTORY_LIMIT = 300;

const BLOCK_DOMAIN_KEY = "block_domain_set";
const BLOCK_URL_KEY    = "block_url_set";
const BLOCK_HISTORY_KEY= "block_history";

// NEW: feedback storage key
const FEEDBACK_KEY = "feedback_items";

const AUTO_CHECK = true;
const MIN_RECHECK_MS = 5 * 60 * 1000;
const VALID_SCHEMES = new Set(["http:", "https:"]);
const BYPASS_MINUTES_DEFAULT = 5;


let session = null;
let featureOrder = null;
let initialized = false;

const lastCheckedAt = new Map();       // url -> ms (throttle per-URL)

const MODEL_PATH = "model/extension.onnx";
const FEATURE_ORDER_PATH = "model/extension_feature_order.json";
const UNSAFE_THRESHOLD = 0.515;

/***** ENABLE / DISABLE (master switch) *****/
const ENABLED_KEY = "ext_enabled";
let EXT_ENABLED = true; // cached toggle state

function updateIcon(enabled) {
  if (enabled) {
    chrome.action.setIcon({
      path: {
        "16": "icon/icon-turnon16.png",
        "48": "icon/icon-turnon48.png",
        "128": "icon/icon-turnon128.png"
      }
    });
  } else {
    chrome.action.setIcon({
      path: {
        "16": "icon/icon-turnoff16.png",
        "48": "icon/icon-turnoff48.png",
        "128": "icon/icon-turnoff128.png"
      }
    });
  }
}

async function fetchArrayBufferRelative(path) {
  const url = chrome.runtime.getURL(path);
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`Failed to fetch ${path} (${resp.status})`);
  return await resp.arrayBuffer();
}

async function fetchJsonRelative(path) {
  const url = chrome.runtime.getURL(path);
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`Failed to fetch JSON ${path} (${resp.status})`);
  return await resp.json();
}

function extractFeaturesFromUrl(url) {
  try {
    const u = new URL(url);
    const hostname = u.hostname;

    const length_url = url.length;
    const length_hostname = hostname.length;
    const ratio_digits_url = (url.match(/\d/g) || []).length / Math.max(1, url.length);
    const ratio_digits_host = (hostname.match(/\d/g) || []).length / Math.max(1, hostname.length);
    const nb_subdomains = Math.max(0, hostname.split(".").length - 2);
    const prefix_suffix = /-|_/.test(hostname) ? 1 : 0;
    const uses_https = u.protocol === "https:" ? 1 : 0;
    const is_http = u.protocol === "http:" ? 1 : 0;
    const num_query_params = u.searchParams ? [...u.searchParams].length : 0;
    const has_at_symbol = url.includes("@") ? 1 : 0;

    let url_entropy = 0;
    const map = {};
    for (const ch of url) map[ch] = (map[ch] || 0) + 1;
    for (const k in map) {
      const p = map[k] / url.length;
      url_entropy -= p * Math.log2(p);
    }

    const url_length_ratio = length_url / (length_hostname + 1);
    const digit_ratio_diff = Math.abs(ratio_digits_url - ratio_digits_host);

    return {
      length_url,
      length_hostname,
      ratio_digits_url,
      ratio_digits_host,
      nb_subdomains,
      tld_in_path: 0,
      tld_in_subdomain: 0,
      shortening_service: 0,
      prefix_suffix,
      url_entropy,
      uses_https,
      is_http,
      num_query_params,
      has_at_symbol,
      path_extension: 0,
      tld_risk: 0,
      typosquat_candidate: 0,
      typosquat_score_max: 0,
      typosquat_score_mean: 0,
      typosquat_distance: 0,
      url_length_ratio,
      digit_ratio_diff
    };
  } catch {
    return null;
  }
}

function buildInputTensor(featuresObj) {
  if (!featureOrder) throw new Error("featureOrder not loaded");
  const arr = new Float32Array(featureOrder.length);
  for (let i = 0; i < featureOrder.length; i++) {
    arr[i] = Number(featuresObj[featureOrder[i]] ?? 0);
  }
  return new ort.Tensor("float32", arr, [1, featureOrder.length]);
}

function readNumberFromTensor(t) {
  try {
    const arr = t?.data;
    if (!arr || arr.length === 0) return null;
    if (arr.length === 2) return typeof arr[1] === "number" ? arr[1] : null;
    if (arr.length === 1) {
      const v = arr[0];
      if (typeof v !== "number") return null;
      if (v < 0 || v > 1) return 1 / (1 + Math.exp(-v));
      return v;
    }
    const last = arr[arr.length - 1];
    return typeof last === "number" ? last : null;
  } catch {
    return null;
  }
}

function readNumberFromMap(m) {
  try {
    const kt = m?.keys, vt = m?.values;
    if (!kt?.data || !vt?.data) return null;
    const keys = kt.data, vals = vt.data;
    let idx = -1;
    for (let i = 0; i < keys.length; i++) {
      const k = String(keys[i]).toLowerCase();
      if (k === "1" || k.includes("unsafe") || k.includes("phishing")) {
        idx = i;
        break;
      }
    }
    if (idx >= 0 && typeof vals[idx] === "number") return vals[idx];
    let max = -Infinity;
    for (let i = 0; i < vals.length; i++) {
      if (vals[i] > max) max = vals[i];
    }
    return isFinite(max) ? max : null;
  } catch {
    return null;
  }
}

function readNumberFromValue(v) {
  if (v && typeof v === "object" && "data" in v) return readNumberFromTensor(v);
  if (v && typeof v === "object" && v.keys && v.values) return readNumberFromMap(v);
  if (Array.isArray(v)) {
    for (const it of v) {
      const n = readNumberFromValue(it);
      if (n != null) return n;
    }
  }
  return null;
}

function pickUnsafeProbabilityFromResults(results, outputNames) {
  const preferred = [
    "probabilities",
    "probability",
    "proba",
    "scores",
    "logits",
    "output_probability",
    "output_prob"
  ];

  for (const name of preferred) {
    if (Object.prototype.hasOwnProperty.call(results, name)) {
      const num = readNumberFromValue(results[name]);
      if (num != null) return num;
    }
  }

  for (const name of (outputNames || [])) {
    if (!Object.prototype.hasOwnProperty.call(results, name)) continue;
    const num = readNumberFromValue(results[name]);
    if (num != null) return num;
  }

  for (const [, v] of Object.entries(results)) {
    const num = readNumberFromValue(v);
    if (num != null) return num;
  }

  return 0;
}

async function createSessionWasmWithFallback(modelBin) {
  ort.env.wasm.wasmPaths = chrome.runtime.getURL("vendor/");
  try {
    ort.env.wasm.numThreads = 1;
    ort.env.wasm.simd = true;
    const s1 = await ort.InferenceSession.create(modelBin, {
      executionProviders: ["wasm"],
      graphOptimizationLevel: "all"
    });
    console.log("✅ ONNX session ready (WASM single-thread)");
    return s1;
  } catch (e1) {
    console.warn("Single-thread failed → try threaded", e1);
  }

  try {
    ort.env.wasm.numThreads = 2;
    ort.env.wasm.simd = true;
    const s2 = await ort.InferenceSession.create(modelBin, {
      executionProviders: ["wasm"],
      graphOptimizationLevel: "all"
    });
    console.log("✅ ONNX session ready (WASM threaded)");
    return s2;
  } catch (e2) {
    console.warn("Threaded WASM failed", e2);
    throw e2;
  }
}

async function preloadModel() {
  if (initialized) {
    console.log("[FX] preloadModel already initialized");
    return { status: "already" };
  }

  try {
    console.log("[FX] preloadModel start");
    console.log("[FX] ort =", globalThis.ort);

    if (!globalThis.ort) {
      throw new Error("ort not found");
    }

    const [modelBin, order] = await Promise.all([
      fetchArrayBufferRelative(MODEL_PATH),
      fetchJsonRelative(FEATURE_ORDER_PATH)
    ]);

    console.log("[FX] model loaded bytes =", modelBin.byteLength);
    console.log("[FX] feature order length =", order?.length);

    featureOrder = order;
    session = await createSessionWasmWithFallback(modelBin);
    initialized = true;

    console.log("[FX] preloadModel success");
    console.log("[FX] inputNames =", session?.inputNames);
    console.log("[FX] outputNames =", session?.outputNames);

    return { status: "ok" };
  } catch (err) {
    console.error("[FX] preloadModel failed =", err);
    return { status: "error", error: String(err) };
  }
}

async function runModelCheck(url) {
  console.log("[FX] runModelCheck url =", url);
  console.log("[FX] initialized =", initialized);

  if (!initialized) {
    const preload = await preloadModel();
    console.log("[FX] preload result =", preload);

    if (preload?.status === "error") {
      return { prediction: 0, unsafe_probability: 0, reason: "model_load_failed" };
    }
  }

  if (!session || !featureOrder) {
    console.log("[FX] model not ready");
    return { prediction: 0, unsafe_probability: 0, reason: "model_not_ready" };
  }

  const features = extractFeaturesFromUrl(url);
  console.log("[FX] features =", features);

  if (!features) {
    return { prediction: 0, unsafe_probability: 0, reason: "feature_extract_failed" };
  }

  try {
    const inputTensor = buildInputTensor(features);
    console.log("[FX] inputTensor =", Array.from(inputTensor.data));

    const feeds = { [session.inputNames[0]]: inputTensor };
    const results = await session.run(feeds);
    console.log("[FX] raw results =", results);

    let unsafe_prob = null;
    const firstName = session.outputNames?.[0];
    const firstOut = firstName ? results[firstName] : null;

    if (firstOut && firstOut.data) {
      unsafe_prob = readNumberFromTensor(firstOut);
    }

    if (unsafe_prob == null) {
      unsafe_prob = pickUnsafeProbabilityFromResults(results, session.outputNames);
    }

    if (!isFinite(unsafe_prob)) unsafe_prob = 0;
    unsafe_prob = Math.max(0, Math.min(1, unsafe_prob));

    const prediction = unsafe_prob >= UNSAFE_THRESHOLD ? 1 : 0;
    console.log("[FX] unsafe_prob =", unsafe_prob, "prediction =", prediction);

    return { prediction, unsafe_probability: unsafe_prob };
  } catch (err) {
    console.error("[FX] inference error =", err);
    return { prediction: 0, unsafe_probability: 0, reason: "inference_error" };
  }
}

function updateBadgeForEnabled(on) {
  if (on) {
    chrome.action.setBadgeText({ text: "" });
    chrome.action.setBadgeBackgroundColor?.({ color: "#16a34a" });
  } else {
    chrome.action.setBadgeText({ text: "OFF" });
    chrome.action.setBadgeBackgroundColor?.({ color: "#9aa0a6" });
  }
}

async function loadEnabled() {
  const obj = await chrome.storage.sync.get(ENABLED_KEY);
  EXT_ENABLED = obj[ENABLED_KEY] !== false;

  updateBadgeForEnabled(EXT_ENABLED);
  updateIcon(EXT_ENABLED);
}

async function setEnabled(on) {
  EXT_ENABLED = !!on;

  await chrome.storage.sync.set({ [ENABLED_KEY]: EXT_ENABLED });

  updateBadgeForEnabled(EXT_ENABLED);
  updateIcon(EXT_ENABLED);
}


/***** ALLOWLIST (CSV + USER) *****/
const ALLOWLIST_CSV_PATH = "data/allowlist.csv";
let ALLOWLIST_SET = null;
let allowlistReadyPromise = null;

// user-allowlist
const ALLOWLIST_USER_KEY = "allowlist_user_set";
let USER_ALLOWLIST_SET = null; // Set<string> ของโดเมน base (eTLD+1)

function normalizeDomainToETLD1(hostname) {
  try {
    const h = String(hostname).toLowerCase().trim();
    const parts = h.split(".").filter(Boolean);
    if (parts.length <= 2) return parts.join(".");
    return parts.slice(-2).join(".");
  } catch {
    return String(hostname || "").toLowerCase().trim();
  }
}

async function loadAllowlistFromCsv() {
  if (ALLOWLIST_SET) return ALLOWLIST_SET;
  if (allowlistReadyPromise) return allowlistReadyPromise;

  allowlistReadyPromise = (async () => {
    const url = chrome.runtime.getURL(ALLOWLIST_CSV_PATH);
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`Failed to fetch allowlist CSV (${resp.status})`);
    const text = await resp.text();

    const set = new Set();
    const lines = text.split(/\r?\n/);
    let headerHandled = false;
    for (const raw of lines) {
      const line = raw.trim();
      if (!line) continue;
      if (!headerHandled && /^domain(?:,|$)/i.test(line)) { headerHandled = true; continue; }
      headerHandled = true;
      let domain = line;
      const parts = line.split(",");
      if (parts.length >= 2) domain = parts[1];
      domain = String(domain).trim().replace(/^"+|"+$/g, "");
      if (!domain) continue;
      set.add(normalizeDomainToETLD1(domain));
    }
    ALLOWLIST_SET = set;
    console.log("✅ Allowlist CSV loaded:", ALLOWLIST_SET.size);
    return ALLOWLIST_SET;
  })();
  return allowlistReadyPromise;
}

async function loadUserAllowlist() {
  if (USER_ALLOWLIST_SET) return USER_ALLOWLIST_SET;
  const obj = await chrome.storage.sync.get(ALLOWLIST_USER_KEY);
  const arr = Array.isArray(obj[ALLOWLIST_USER_KEY]) ? obj[ALLOWLIST_USER_KEY] : [];
  USER_ALLOWLIST_SET = new Set(arr.map(normalizeDomainToETLD1));
  return USER_ALLOWLIST_SET;
}

async function saveUserAllowlist(set) {
  await chrome.storage.sync.set({ [ALLOWLIST_USER_KEY]: Array.from(set) });
  chrome.runtime.sendMessage({ action: "allowlist_updated" }).catch(()=>{});
}

function isAllowedByAny(hostname) {
  const base = normalizeDomainToETLD1(hostname);
  return (ALLOWLIST_SET && ALLOWLIST_SET.has(base)) || (USER_ALLOWLIST_SET && USER_ALLOWLIST_SET.has(base));
}

/***** STORAGE: history + blocklists + feedback *****/
async function loadHistory() {
  const obj = await chrome.storage.local.get(HISTORY_KEY);
  return Array.isArray(obj[HISTORY_KEY]) ? obj[HISTORY_KEY] : [];
}
async function saveHistory(hist) {
  if (hist.length > HISTORY_LIMIT) hist.splice(0, hist.length - HISTORY_LIMIT);
  await chrome.storage.local.set({ [HISTORY_KEY]: hist });
  chrome.runtime.sendMessage({ action: "history_updated" }).catch(() => {});
}
async function appendHistory(entry) {
  const hist = await loadHistory();
  hist.push(entry);
  await saveHistory(hist);
}

async function loadBlocks() {
  const obj = await chrome.storage.local.get([BLOCK_DOMAIN_KEY, BLOCK_URL_KEY]);
  return {
    domains: Array.isArray(obj[BLOCK_DOMAIN_KEY]) ? new Set(obj[BLOCK_DOMAIN_KEY]) : new Set(),
    urls: Array.isArray(obj[BLOCK_URL_KEY]) ? new Set(obj[BLOCK_URL_KEY]) : new Set(),
  };
}
async function saveBlocks(domainsSet, urlsSet) {
  await chrome.storage.local.set({
    [BLOCK_DOMAIN_KEY]: Array.from(domainsSet),
    [BLOCK_URL_KEY]: Array.from(urlsSet)
  });
  await rebuildDnrRules(); // refresh DNR
  chrome.runtime.sendMessage({ action: "blocks_updated" }).catch(() => {});
}
async function addBlockDomainFromUrl(url, who = "manual") {
  const base = normalizeDomainToETLD1(safeDomain(url));
  const { domains, urls } = await loadBlocks();
  domains.add(base);
  await saveBlocks(domains, urls);
  await appendBlockHistory({ type:"domain", value: base, url, ts: nowISO(), who });
}
async function addBlockUrl(url, who = "manual") {
  const { domains, urls } = await loadBlocks();
  urls.add(url);
  await saveBlocks(domains, urls);
  await appendBlockHistory({ type:"url", value: url, url, ts: nowISO(), who });
}
async function removeBlockDomain(domain) {
  const { domains, urls } = await loadBlocks();
  domains.delete(domain);
  await saveBlocks(domains, urls);
}
async function removeBlockUrl(url) {
  const { domains, urls } = await loadBlocks();
  urls.delete(url);
  await saveBlocks(domains, urls);
}

async function getBlockHistory() {
  const obj = await chrome.storage.local.get(BLOCK_HISTORY_KEY);
  return Array.isArray(obj[BLOCK_HISTORY_KEY]) ? obj[BLOCK_HISTORY_KEY] : [];
}
async function setBlockHistory(arr) {
  await chrome.storage.local.set({ [BLOCK_HISTORY_KEY]: arr });
  chrome.runtime.sendMessage({ action: "block_history_updated" }).catch(() => {});
}
async function appendBlockHistory(entry) {
  const arr = await getBlockHistory();
  arr.push(entry);
  await setBlockHistory(arr);
}

// NEW: feedback storage helpers
async function loadFeedback() {
  const obj = await chrome.storage.local.get(FEEDBACK_KEY);
  return Array.isArray(obj[FEEDBACK_KEY]) ? obj[FEEDBACK_KEY] : [];
}
async function saveFeedback(arr) {
  await chrome.storage.local.set({ [FEEDBACK_KEY]: arr });
  chrome.runtime.sendMessage({ action: "feedback_updated" }).catch(()=>{});
}
async function appendFeedback(entry) {
  const arr = await loadFeedback();
  arr.push(entry);
  await saveFeedback(arr);
}

/***** UTILS *****/
function nowISO() { return new Date().toISOString(); }
function safeDomain(url) { try { return new URL(url).hostname; } catch { return ""; } }
function shouldAutoCheck(url) {
  try { if (!VALID_SCHEMES.has(new URL(url).protocol)) return false; } catch { return false; }
  const last = lastCheckedAt.get(url) || 0;
  return (Date.now() - last) > MIN_RECHECK_MS;
}
function escapeRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

function toFirestoreDoc(data) {
  const fields = {};

  for (const [k, v] of Object.entries(data)) {
    if (Array.isArray(v)) {
      fields[k] = {
        arrayValue: {
          values: v.map(x => ({ stringValue: String(x) }))
        }
      };
    } else if (typeof v === "string") {
      fields[k] = { stringValue: v };
    } else if (typeof v === "number") {
      fields[k] = { doubleValue: v };
    } else if (typeof v === "boolean") {
      fields[k] = { booleanValue: v };
    } else {
      fields[k] = { stringValue: String(v) };
    }
  }

  fields.ts = { timestampValue: new Date().toISOString() };

  return { fields };
}


/***** BYPASS (ต่อแท็บ สำหรับ model-unsafe เท่านั้น) *****/
const bypassMap = new Map(); // tabId -> { base: expireMs, ... }
function setBypass(tabId, base, minutes = BYPASS_MINUTES_DEFAULT) {
  const until = Date.now() + minutes * 60 * 1000;
  const cur = bypassMap.get(tabId) || {};
  cur[base] = until;
  bypassMap.set(tabId, cur);
}
function hasBypass(tabId, base) {
  const cur = bypassMap.get(tabId);
  if (!cur) return false;
  const exp = cur[base];
  if (!exp) return false;
  if (Date.now() > exp) { delete cur[base]; return false; }
  return true;
}

/***** DNR: block ก่อนโหลดจริง *****/
const DNR_RULE_ID_START = 1000;
const DNR_MAX_RULES = 5000;

function ruleForBlockedUrl(id, fullUrl) {
  return {
    id,
    priority: 2,
    action: {
      type: "redirect",
      redirect: {
        regexSubstitution: chrome.runtime.getURL("warning.html") + "?url=\\0&why=blocked:url"
      }
    },
    condition: {
      regexFilter: "^" + escapeRe(fullUrl) + "$",
      resourceTypes: ["main_frame"]
    }
  };
}
function ruleForBlockedDomain(id, domain) {
  return {
    id,
    priority: 1,
    action: {
      type: "redirect",
      redirect: {
        regexSubstitution:
          chrome.runtime.getURL("warning.html") +
          "?domain=" + encodeURIComponent(domain) +
          "&why=blocked:domain"
      }
    },
    condition: {
      requestDomains: [domain],
      resourceTypes: ["main_frame"]
    }
  };
}
async function rebuildDnrRules() {
  const { domains, urls } = await loadBlocks();
  const rules = [];
  let nextId = DNR_RULE_ID_START;

  for (const u of urls) {
    rules.push(ruleForBlockedUrl(nextId++, u));
    if (rules.length >= DNR_MAX_RULES) break;
  }
  for (const d of domains) {
    rules.push(ruleForBlockedDomain(nextId++, d));
    if (rules.length >= DNR_MAX_RULES) break;
  }

  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const toRemove = existing.map(r => r.id);
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: toRemove, addRules: rules });

  console.log("✅ DNR rules updated:", rules.length);
}

/***** MODEL CHECK + INTERSTITIAL (เฉพาะไม่โดน DNR กันไว้) *****/
async function checkUrlSafety(url) {
  console.log("[FX] checkUrlSafety url =", url);

  const host = safeDomain(url);
  try { await loadAllowlistFromCsv(); } catch {}
  await loadUserAllowlist().catch(()=>{});

  if (isAllowedByAny(host)) {
    const reason = (USER_ALLOWLIST_SET && USER_ALLOWLIST_SET.has(normalizeDomainToETLD1(host)))
      ? "allowlist-hard:user"
      : "allowlist-hard:csv";
    console.log("[FX] allowlist matched =", reason);
    return { prediction: 0, unsafe_probability: 0.001, reason };
  }

  try {
    const res = await runModelCheck(url);
    console.log("[FX] model result =", res);
    if (!res) throw new Error("no model response");
    return res;
  } catch (e) {
    console.error("[FX] checkUrlSafety error =", e);
    return { prediction: 0, unsafe_probability: 0, reason: "check_error" };
  }
}


/***** เก็บประวัติ URL ของแท็บ (main_frame) เพื่อ safeBackTarget *****/
const tabHistoryMap = new Map(); // tabId -> string[]
const tabSafeBack = new Map();   // tabId -> url

function pushTabHistory(tabId, url) {
  if (!url) return;
  const warnPrefix = chrome.runtime.getURL("warning.html");
  if (url.startsWith(warnPrefix)) return; // ไม่เก็บหน้าเตือน
  const arr = tabHistoryMap.get(tabId) || [];
  if (arr[arr.length - 1] !== url) arr.push(url);
  if (arr.length > 30) arr.splice(0, arr.length - 30);
  tabHistoryMap.set(tabId, arr);
}

chrome.webNavigation.onCommitted.addListener((details) => {
  try {
    if (details.frameId !== 0) return;
    if (!details.url) return;

    if (shouldSkipUrl(details.url)) return;  

    pushTabHistory(details.tabId, details.url);
    autoCheckTabUrl(details.tabId, details.url);

  } catch {}
});


/***** ===== helper: run auto-check for a given tab+url (guarded) ===== *****/
async function autoCheckTabUrl(tabId, url) {
  try {
    if (!EXT_ENABLED) return;
    if (!url) return;
    if (shouldSkipUrl(url)) return;

    // ไม่ตรวจหน้าเตือนของเราเอง
    const warnPrefix = chrome.runtime.getURL("warning.html");
    if (url.startsWith(warnPrefix)) return;

    // เฉพาะ http/https
    try { if (!VALID_SCHEMES.has(new URL(url).protocol)) return; } catch { return; }

    // กันยิงถี่
    if (!shouldAutoCheck(url)) return;

    const host = safeDomain(url);
    const base = normalizeDomainToETLD1(host);

    // ⛳ BYPASS-FIX: ยังตรวจ/บันทึก แต่จะไม่แสดง interstitial ถ้าอยู่ในช่วง bypass
    const bypassed = hasBypass(tabId, base);

    lastCheckedAt.set(url, Date.now());

    const { prediction, unsafe_probability, reason } = await checkUrlSafety(url);

    const item = {
      url,
      domain: host,
      prob: Number(unsafe_probability || 0),
      prediction: Number(prediction || 0),
      ts: nowISO(),
      source: reason
        ? (bypassed ? `auto:bypass:${reason}` : `auto:${reason}`)
        : (bypassed ? "auto:bypass" : "auto")
    };
    await appendHistory(item);

    chrome.action.setBadgeText({ text: item.prediction ? "⚠" : "", tabId });
    chrome.action.setBadgeBackgroundColor({ color: item.prediction ? "#d9534f" : "#2ecc71", tabId });

    if (item.prediction === 1 && !bypassed) {
      const hist = tabHistoryMap.get(tabId) || [];
      const safeBackTarget = hist.length >= 1 ? hist[hist.length - 1] : null;
      if (safeBackTarget) tabSafeBack.set(tabId, safeBackTarget);

      const interstitial = chrome.runtime.getURL(
        `warning.html?url=${encodeURIComponent(url)}&tabId=${tabId}&why=model-unsafe`
      );
      await chrome.tabs.update(tabId, { url: interstitial });
    }
  } catch (e) {
    console.warn("autoCheckTabUrl error:", e);
  }
}

/***** AUTO CHECK (page load แบบปกติ) *****/
if (AUTO_CHECK) {
  chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    try {
      if (changeInfo.status !== "loading") return;
      if (!EXT_ENABLED) return;

      const url = tab?.url || "";
      if (shouldSkipUrl(url)) return;
      autoCheckTabUrl(tabId, url);
    } catch (e) {
      console.warn("auto-check error:", e);
    }
  });
}

const lastUrlMap = new Map();

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  try {
    if (!changeInfo.url) return;

    if (shouldSkipUrl(changeInfo.url)) return;

    const prev = lastUrlMap.get(tabId);

    if (prev && prev !== changeInfo.url) {
      // 🔥 redirect detected
      autoCheckTabUrl(tabId, prev);   // เช็คตัวต้นทาง
    }

    lastUrlMap.set(tabId, changeInfo.url);

  } catch (e) {
    console.warn("redirect detect error", e);
  }
});

/***** ✅ SPA / fragment / soft-redirect hooks *****/
// SPA (history.pushState / replaceState)
chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  try {
    if (details.frameId !== 0) return;
    autoCheckTabUrl(details.tabId, details.url);
  } catch (e) { console.warn("onHistoryStateUpdated err", e); }
}, { url: [{ schemes: ["http", "https"] }] });

// #fragment เปลี่ยน
chrome.webNavigation.onReferenceFragmentUpdated.addListener((details) => {
  try {
    if (details.frameId !== 0) return;
    autoCheckTabUrl(details.tabId, details.url);
  } catch (e) { console.warn("onReferenceFragmentUpdated err", e); }
}, { url: [{ schemes: ["http", "https"] }] });

// บางเว็บอัปเดต changeInfo.url โดยไม่เข้าสถานะ loading (soft redirect)
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  try {
    if (typeof changeInfo?.url === "string" && changeInfo.url) {
      if (shouldSkipUrl(changeInfo.url)) return;
      autoCheckTabUrl(tabId, changeInfo.url);
    }
  } catch (e) { console.warn("tabs.onUpdated(url) err", e); }
});

/***** SMART BACK + SAFE BACK *****/
function isWarningUrl(url) {
  const warn = chrome.runtime.getURL("warning.html");
  return typeof url === "string" && url.startsWith(warn);
}
async function isUrlBlockedByUserLists(url) {
  try {
    const { domains, urls } = await loadBlocks();
    if (urls.has(url)) return true;
    const host = safeDomain(url);
    const base = normalizeDomainToETLD1(host);
    if (domains.has(base)) return true;
    return false;
  } catch {
    return false;
  }
}
async function stillBlockedOrWarning(url) {
  if (!url) return true;
  if (isWarningUrl(url)) return true;
  if (await isUrlBlockedByUserLists(url)) return true;
  return false;
}
function delay(ms) { return new Promise(r => setTimeout(r, ms)); }
async function getTabUrlStable(tabId, tries = 20, gap = 120) {
  let last = "";
  for (let i = 0; i < tries; i++) {
    try {
      const t = await chrome.tabs.get(tabId);
      if (t?.url) {
        if (t.url !== last) {
          last = t.url;
          await delay(gap);
          const t2 = await chrome.tabs.get(tabId);
          return t2?.url || t?.url || "";
        }
      }
    } catch {}
    await delay(gap);
  }
  return last;
}
async function smartBack(tabId, maxSteps = 15) {
  if (typeof tabId !== "number") {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      tabId = tab?.id;
    } catch {}
  }
  if (typeof tabId !== "number") return { ok:false, error:"no-tab" };

  let steps = 0;
  while (steps < maxSteps) {
    steps++;

    const ok = await new Promise(res => {
      try {
        chrome.tabs.goBack(tabId, () => {
          if (chrome.runtime.lastError) return res(false);
          res(true);
        });
      } catch { res(false); }
    });
    if (!ok) break;

    await delay(200);

    const curUrl = await getTabUrlStable(tabId, 20, 120);
    if (!curUrl) continue;

    const bad = await stillBlockedOrWarning(curUrl);
    if (!bad) return { ok:true, url: curUrl, steps };
  }

  try { await chrome.tabs.update(tabId, { url: "about:blank" }); } catch {}
  return { ok:false, error:"exhausted", steps };
}

function shouldSkipUrl(url) {
  if (!url) return true;

  return (
    url.startsWith("chrome://") ||
    url.startsWith("edge://") ||
    url.startsWith("about:") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("moz-extension://") ||
    url.includes("ntp.msn.com") ||
    url.includes("newtab") ||
    url.includes("_generated_background_page")
  );
}
/***** API (popup + warning + allowlist user + feedback + enabled) *****/
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // History
  if (msg?.action === "get_history") {
    (async () => {
      const hist = await loadHistory();
      hist.sort((a, b) => (a.ts > b.ts ? -1 : 1));
      const limit = Math.min(Number(msg.limit || 100), HISTORY_LIMIT);
      sendResponse({ ok: true, items: hist.slice(0, limit) });
    })();
    return true;
  }
  if (msg?.action === "clear_history") {
    (async () => { await saveHistory([]); lastCheckedAt.clear(); sendResponse({ ok: true }); })();
    return true;
  }

  // Blocks
  if (msg?.action === "get_blocks") {
    (async () => {
      const { domains, urls } = await loadBlocks();
      sendResponse({ ok: true, domains: Array.from(domains), urls: Array.from(urls) });
    })();
    return true;
  }
  if (msg?.action === "remove_block_domain") {
    (async () => { await removeBlockDomain(msg.domain); sendResponse({ ok: true }); })();
    return true;
  }
  if (msg?.action === "remove_block_url") {
    (async () => { await removeBlockUrl(msg.url); sendResponse({ ok: true }); })();
    return true;
  }
  if (msg?.action === "get_block_history") {
    (async () => {
      const arr = await getBlockHistory();
      arr.sort((a, b) => (a.ts > b.ts ? -1 : 1));
      sendResponse({ ok: true, items: arr.slice(0, Number(msg.limit || 200)) });
    })();
    return true;
  }
  if (msg?.action === "clear_block_history") {
    (async () => { await setBlockHistory([]); sendResponse({ ok: true }); })();
    return true;
  }

  // Warning page actions
  if (msg?.action === "bypass_once") {
    (async () => {
      try {
        const base = normalizeDomainToETLD1(safeDomain(msg.url));
        const minutes = Number(msg.minutes || BYPASS_MINUTES_DEFAULT);
        if (msg.tabId != null) setBypass(Number(msg.tabId), base, minutes);
        sendResponse({ ok: true });
      } catch (e) { sendResponse({ ok: false, error: String(e) }); }
    })();
    return true;
  }
  if (msg?.action === "block_add_domain") {
    (async () => { await addBlockDomainFromUrl(msg.url, msg.reason || "manual"); sendResponse({ ok: true }); })();
    return true;
  }
  if (msg?.action === "block_add_url") {
    (async () => { await addBlockUrl(msg.url, msg.reason || "manual"); sendResponse({ ok: true }); })();
    return true;
  }
  if (msg?.action === "notify_blocked") {
    chrome.notifications?.create({
      type: "basic",
      iconUrl: "icon/icon-turnon128.png",
      title: "เว็บไซต์ถูกบล็อค",
      message: `${msg.why || "blocked"}\n${msg.url || ""}`
    }, () => {});
    sendResponse({ ok: true });
    return true;
  }

  // safe back / smart back
  if (msg?.action === "go_safe_back") {
    (async () => {
      let tabId = typeof msg.tabId === "number" ? msg.tabId : undefined;
      const fallbackSteps = Number(msg.fallbackSteps || 15);

      if (typeof tabId !== "number") {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        tabId = tab?.id;
      }
      if (typeof tabId !== "number") return sendResponse({ ok:false, error:"no-tab" });

      const target = tabSafeBack.get(tabId);
      if (target) {
        try {
          await chrome.tabs.update(tabId, { url: target });
          return sendResponse({ ok:true, url: target, used: "safeBackTarget" });
        } catch {}
      }
      const result = await smartBack(tabId, fallbackSteps);
      sendResponse({ ok: result.ok, url: result.url, used: "smart_back", steps: result.steps });
    })();
    return true;
  }
  if (msg?.action === "smart_back") {
    (async () => {
      const tabId = typeof msg.tabId === "number" ? msg.tabId : undefined;
      const maxSteps = Number(msg.maxSteps || 15);
      const result = await smartBack(tabId, maxSteps);
      sendResponse(result);
    })();
    return true;
  }

  // Manual check
  if (msg?.action === "manual_check_active_tab") {
    (async () => {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab?.url) return sendResponse({ ok: false, error: "No active tab URL" });
        const u = new URL(tab.url);
        if (!["http:", "https:"].includes(u.protocol)) {
          return sendResponse({ ok: false, error: "หน้านี้ไม่ใช่เว็บไซต์ (protocol ไม่ใช่ http/https)" });
        }

        if (!EXT_ENABLED) {
          return sendResponse({ ok:false, error:"ส่วนขยายถูกปิดการทำงาน (OFF)" });
        }

        const { prediction, unsafe_probability, reason } = await checkUrlSafety(tab.url);
        const item = {
          url: tab.url,
          domain: safeDomain(tab.url),
          prob: Number(unsafe_probability || 0),
          prediction: Number(prediction || 0),
          ts: nowISO(),
          source: reason ? `manual:${reason}` : "manual"
        };
        await appendHistory(item);
        chrome.action.setBadgeText({ text: item.prediction ? "⚠" : "", tabId: tab.id });
        chrome.action.setBadgeBackgroundColor({ color: item.prediction ? "#d9534f" : "#2ecc71", tabId: tab.id });
        sendResponse({ ok: true, item });
      } catch (e) { sendResponse({ ok: false, error: String(e) }); }
    })();
    return true;
  }

  // Preload model (optional)
  if (msg?.action === "preload_model") {
    (async () => {
      try {
        await preloadModel();
        sendResponse({ status: "ok" });
      } catch (e) {
        sendResponse({ status: "error", error: String(e) });
      }
    })();
    return true;
  }

  // ======= ENABLED APIs (master switch) =======
  if (msg?.action === "get_enabled") {
    (async () => {
      if (typeof EXT_ENABLED !== "boolean") await loadEnabled();
      sendResponse({ ok: true, enabled: EXT_ENABLED });
    })();
    return true;
  }
  if (msg?.action === "set_enabled") {
    (async () => {
      await setEnabled(!!msg.enabled);
      sendResponse({ ok: true });
    })();
    return true;
  }

  // ======= USER ALLOWLIST APIs =======
  if (msg?.action === "get_allowlist") {
    (async () => {
      await loadUserAllowlist();
      sendResponse({ ok: true, domains: Array.from(USER_ALLOWLIST_SET || []) });
    })();
    return true;
  }
  if (msg?.action === "allow_add_domain") {
    (async () => {
      try {
        const base = normalizeDomainToETLD1(msg.domain || "");
        if (!base) return sendResponse({ ok:false, error:"invalid-domain" });
        await loadUserAllowlist();
        USER_ALLOWLIST_SET.add(base);
        await saveUserAllowlist(USER_ALLOWLIST_SET);
        sendResponse({ ok: true });
      } catch (e) { sendResponse({ ok:false, error:String(e) }); }
    })();
    return true;
  }
  if (msg?.action === "allow_remove_domain") {
    (async () => {
      try {
        const base = normalizeDomainToETLD1(msg.domain || "");
        await loadUserAllowlist();
        USER_ALLOWLIST_SET.delete(base);
        await saveUserAllowlist(USER_ALLOWLIST_SET);
        sendResponse({ ok: true });
      } catch (e) { sendResponse({ ok:false, error:String(e) }); }
    })();
    return true;
  }
  if (msg?.action === "check_allowlisted_host") {
    (async () => {
      try {
        await loadAllowlistFromCsv();
        await loadUserAllowlist();
        const base = normalizeDomainToETLD1(msg.domain || "");
        const inCsv  = !!ALLOWLIST_SET?.has(base);
        const inUser = !!USER_ALLOWLIST_SET?.has(base);
        const allowlisted = inCsv || inUser;
        const source = inUser ? "user" : (inCsv ? "csv" : null);
        sendResponse({ ok: true, allowlisted, base, source });
      } catch (e) { sendResponse({ ok:false, error:String(e) }); }
    })();
    return true;
  }
// ======= FEEDBACK APIs =======

// 1) เก็บ feedback ลง local storage (ของเดิมคุณ)
if (msg?.action === "feedback_add") {
  (async () => {
    try {
      const entry = {
        ts: nowISO(),
        url: msg.url || "",
        domain: msg.domain || "",
        model_label: msg.model_label || "",   // SAFE / SUSPECT / UNSAFE
        user_claim: msg.user_claim || "",     // not_phishing | is_phishing
        flags: Array.isArray(msg.flags) ? msg.flags.slice(0, 50) : [],
        note: String(msg.note || "").slice(0, 2000)
      };
      await appendFeedback(entry);
      sendResponse({ ok: true });
    } catch (e) {
      sendResponse({ ok: false, error: String(e) });
    }
  })();
  return true;
}

// 2) list feedback (local)
if (msg?.action === "feedback_list") {
  (async () => {
    const items = await loadFeedback();
    items.sort((a, b) => (a.ts > b.ts ? -1 : 1));
    sendResponse({ ok: true, items });
  })();
  return true;
}

// 3) clear feedback (local)
if (msg?.action === "feedback_clear") {
  (async () => {
    await saveFeedback([]);
    sendResponse({ ok: true });
  })();
  return true;
}

// 4) ส่ง feedback เข้า Firestore (ใหม่)
if (msg?.action === "feedback_send_firestore") {
  (async () => {
    try {
      const doc = toFirestoreDoc({
        url: msg.url || "",
        domain: msg.domain || "",
        model_label: msg.model_label || "",
        user_claim: msg.user_claim || "",
        flags: Array.isArray(msg.flags) ? msg.flags.slice(0, 50) : [],
        note: String(msg.note || "").slice(0, 2000),
        source: "firefox_extension"
      });

      const res = await fetch(FIRESTORE_FEEDBACK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(doc)
      });

      sendResponse({ ok: res.ok, status: res.status });
    } catch (e) {
      sendResponse({ ok: false, error: String(e) });
    }
  })();
  return true;
}

// 5) เก็บ local + ส่ง Firestore พร้อมกัน (แนะนำให้ใช้ตัวนี้)
if (msg?.action === "feedback_add_and_send") {
  (async () => {
    try {
      const entry = {
        ts: nowISO(),
        url: msg.url || "",
        domain: msg.domain || "",
        model_label: msg.model_label || "",
        user_claim: msg.user_claim || "",
        flags: Array.isArray(msg.flags) ? msg.flags.slice(0, 50) : [],
        note: String(msg.note || "").slice(0, 2000),
        email: msg.allow_email ? String(msg.email || "").slice(0, 200) : ""
      };
      

      // เก็บ local ก่อน (กันเน็ตล่ม)
      await appendFeedback(entry);

      // ส่ง Firestore
      const doc = toFirestoreDoc({
        ...entry,
        source: "firefox_extension"
      });

      const res = await fetch(FIRESTORE_FEEDBACK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(doc)
      });

      sendResponse({ ok: res.ok, status: res.status });
    } catch (e) {
      sendResponse({ ok: false, error: String(e) });
    }
  })();
  return true;
}

});

/***** WELCOME / ONBOARDING + SYNC DEFAULT *****/
chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === "install") {
    await chrome.storage.sync.set({
      [ENABLED_KEY]: true,
      [ALLOWLIST_USER_KEY]: []
    });

    chrome.tabs.create({
      url: chrome.runtime.getURL("welcome.html")
    });

  } else if (details.reason === "update") {
    // temporarily disabled during Firefox port
  }
});


/***** INIT *****/
chrome.runtime.onStartup?.addListener(() => {
  loadEnabled().catch(()=>{});
  loadAllowlistFromCsv().catch(()=>{});
  loadUserAllowlist().catch(()=>{});
  rebuildDnrRules().catch(()=>{});
});
loadEnabled().catch(()=>{});
loadAllowlistFromCsv().catch(()=>{});
loadUserAllowlist().catch(()=>{});
rebuildDnrRules().catch(()=>{});
