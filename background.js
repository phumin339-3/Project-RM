// background.js — allowlist CSV + DNR block (domain/URL) + auto model check + interstitial + history
// + notifications + offscreen handshake + SAFE BACK TARGET + SMART BACK + welcome on install
// + USER ALLOWLIST (add/remove via popup)
// + FEEDBACK (add/list/clear + export handled in page)
// + MASTER ENABLE SWITCH (ON/OFF) wired to popup

/***** CONFIG *****/
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

const lastCheckedAt = new Map();       // url -> ms
let offscreenReadyWaiter = null;

/***** ENABLE / DISABLE (master switch) *****/
const ENABLED_KEY = "ext_enabled";
let EXT_ENABLED = true; // cached toggle state

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
  const obj = await chrome.storage.local.get(ENABLED_KEY);
  EXT_ENABLED = obj[ENABLED_KEY] !== false; // default true
  updateBadgeForEnabled(EXT_ENABLED);
  return EXT_ENABLED;
}
async function setEnabled(on) {
  EXT_ENABLED = !!on;
  await chrome.storage.local.set({ [ENABLED_KEY]: EXT_ENABLED });
  updateBadgeForEnabled(EXT_ENABLED);
  chrome.runtime.sendMessage({ action: "enabled_changed", enabled: EXT_ENABLED }).catch(()=>{});
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
  const obj = await chrome.storage.local.get(ALLOWLIST_USER_KEY);
  const arr = Array.isArray(obj[ALLOWLIST_USER_KEY]) ? obj[ALLOWLIST_USER_KEY] : [];
  USER_ALLOWLIST_SET = new Set(arr.map(normalizeDomainToETLD1));
  return USER_ALLOWLIST_SET;
}
async function saveUserAllowlist(set) {
  await chrome.storage.local.set({ [ALLOWLIST_USER_KEY]: Array.from(set) });
  chrome.runtime.sendMessage({ action: "allowlist_updated" }).catch(()=>{});
}
function isAllowedByAny(hostname) {
  const base = normalizeDomainToETLD1(hostname);
  return (ALLOWLIST_SET && ALLOWLIST_SET.has(base)) || (USER_ALLOWLIST_SET && USER_ALLOWLIST_SET.has(base));
}

/***** OFFSCREEN HANDSHAKE (ONNX) *****/
function waitForOffscreenReady(timeoutMs = 7000) {
  if (offscreenReadyWaiter) return offscreenReadyWaiter;
  offscreenReadyWaiter = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      chrome.runtime.onMessage.removeListener(handler);
      offscreenReadyWaiter = null;
      reject(new Error("offscreenReady timeout"));
    }, timeoutMs);
    function handler(msg) {
      if (msg?.action === "offscreenReady") {
        clearTimeout(timer);
        chrome.runtime.onMessage.removeListener(handler);
        offscreenReadyWaiter = null;
        resolve(true);
      }
    }
    chrome.runtime.onMessage.addListener(handler);
  });
  return offscreenReadyWaiter;
}
async function ensureOffscreen() {
  try {
    if (await chrome.offscreen.hasDocument()) {
      const res = await chrome.runtime.sendMessage({ action: "ping" }).catch(() => null);
      if (res?.ok) return;
    }
  } catch {}
  await chrome.offscreen.createDocument({
    url: chrome.runtime.getURL("offscreen.html"),
    reasons: [chrome.offscreen.Reason.BLOBS],
    justification: "Run ONNX (WASM) for URL safety scoring"
  });
  await waitForOffscreenReady().catch(() => {});
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
  const ext = new URL(chrome.runtime.getURL("/"));
  return {
    id,
    priority: 1,
    action: {
      type: "redirect",
      redirect: {
        transform: {
          scheme: "chrome-extension",
          host: ext.host,
          path: "/warning.html",
          queryTransform: {
            addOrReplaceParams: [
              { key: "why", value: "blocked:domain" },
              { key: "domain", value: domain }
            ]
          }
        }
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
  const host = safeDomain(url);
  try { await loadAllowlistFromCsv(); } catch {}
  await loadUserAllowlist().catch(()=>{});

  if (isAllowedByAny(host)) {
    const reason = (USER_ALLOWLIST_SET && USER_ALLOWLIST_SET.has(normalizeDomainToETLD1(host)))
      ? "allowlist-hard:user"
      : "allowlist-hard:csv";
    return { prediction: 0, unsafe_probability: 0.001, reason };
  }
  try {
    await ensureOffscreen();
    const res = await chrome.runtime.sendMessage({ action: "check_url", url });
    if (!res) throw new Error("no response from offscreen");
    return res; // { prediction, unsafe_probability }
  } catch (e) {
    console.warn("checkUrlSafety error:", e);
    return { prediction: 0, unsafe_probability: 0 };
  }
}

/***** เก็บประวัติ URL ของแท็บ (main_frame) เพื่อ safeBackTarget *****/
const tabHistoryMap = new Map(); // tabId -> string[]
const tabSafeBack = new Map();   // tabId -> string

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
    if (details.frameId !== 0) return; // main_frame เท่านั้น
    if (details.url) pushTabHistory(details.tabId, details.url);
  } catch {}
});

/***** AUTO CHECK *****/
if (AUTO_CHECK) {
  chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    try {
      if (changeInfo.status !== "loading") return;

      // ⛔ ปิดสวิตช์อยู่ก็ไม่ตรวจอะไรเลย
      if (!EXT_ENABLED) return;

      const url = tab?.url || "";
      if (!shouldAutoCheck(url)) return;

      const host = safeDomain(url);
      const base = normalizeDomainToETLD1(host);
      if (hasBypass(tabId, base)) return;

      lastCheckedAt.set(url, Date.now());

      const { prediction, unsafe_probability, reason } = await checkUrlSafety(url);

      const item = {
        url,
        domain: host,
        prob: Number(unsafe_probability || 0),
        prediction: Number(prediction || 0),
        ts: nowISO(),
        source: reason ? `auto:${reason}` : "auto"
      };
      await appendHistory(item);

      chrome.action.setBadgeText({ text: item.prediction ? "⚠" : "", tabId });
      chrome.action.setBadgeBackgroundColor({ color: item.prediction ? "#d9534f" : "#2ecc71", tabId });

      if (item.prediction === 1) {
        const hist = tabHistoryMap.get(tabId) || [];
        const safeBackTarget = hist.length >= 1 ? hist[hist.length - 1] : null;
        if (safeBackTarget) tabSafeBack.set(tabId, safeBackTarget);

        const interstitial = chrome.runtime.getURL(
          `warning.html?url=${encodeURIComponent(url)}&tabId=${tabId}&why=model-unsafe`
        );
        await chrome.tabs.update(tabId, { url: interstitial });
      }
    } catch (e) {
      console.warn("auto-check error:", e);
    }
  });
}

/***** ✅ REDIRECT LOGGING: บันทึกลิงก์ต้นทางก่อน redirect *****/
// จับเฉพาะ main_frame; ใช้สิทธิ์ webRequest (observe) ไม่บล็อค
chrome.webRequest.onBeforeRedirect.addListener(async (details) => {
  try {
    if (details.frameId !== 0) return;     // เฟรมหลักเท่านั้น
    if (!EXT_ENABLED) return;              // สวิตช์ปิดอยู่ ข้าม
    const fromUrl = details.url;           // URL ก่อนถูก redirect
    // const toUrl = details.redirectUrl;  // ปลายทาง — จะถูกบันทึกโดย onUpdated เดิมอยู่แล้ว

    // กรองเฉพาะ http/https
    try { if (!/^https?:$/.test(new URL(fromUrl).protocol)) return; } catch { return; }

    // ป้องกันยิงซ้ำติดกัน
    if (!shouldAutoCheck(fromUrl)) return;
    lastCheckedAt.set(fromUrl, Date.now());

    // ตรวจและบันทึก “ลิงก์ต้นทาง”
    const { prediction, unsafe_probability, reason } = await checkUrlSafety(fromUrl);
    const item = {
      url: fromUrl,
      domain: safeDomain(fromUrl),
      prob: Number(unsafe_probability || 0),
      prediction: Number(prediction || 0),
      ts: nowISO(),
      source: reason ? `redirect:from:${reason}` : "redirect:from"
    };
    await appendHistory(item);
  } catch (e) {
    console.warn("onBeforeRedirect error:", e);
  }
}, { urls: ["<all_urls>"], types: ["main_frame"] });

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
      iconUrl: "icons/icon128.png",
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
        await ensureOffscreen();
        const res = await chrome.runtime.sendMessage({ action: "preload_model" });
        sendResponse(res);
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
  if (msg?.action === "feedback_add") {
    (async () => {
      try {
        const entry = {
          ts: nowISO(),
          url: msg.url || "",
          domain: msg.domain || "",
          model_label: msg.model_label || "",   // SAFE/SUSPECT/UNSAFE
          user_claim: msg.user_claim || "",     // "not_phishing" | "is_phishing"
          flags: Array.isArray(msg.flags) ? msg.flags.slice(0, 50) : [],
          note: String(msg.note || "").slice(0, 2000)
        };
        await appendFeedback(entry);
        sendResponse({ ok: true });
      } catch (e) { sendResponse({ ok:false, error:String(e) }); }
    })();
    return true;
  }
  if (msg?.action === "feedback_list") {
    (async () => {
      const items = await loadFeedback();
      items.sort((a,b)=> (a.ts > b.ts ? -1 : 1));
      sendResponse({ ok:true, items });
    })();
    return true;
  }
  if (msg?.action === "feedback_clear") {
    (async () => {
      await saveFeedback([]);
      sendResponse({ ok:true });
    })();
    return true;
  }

});

/***** WELCOME / ONBOARDING *****/
chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === "install") {
    chrome.tabs.create({ url: chrome.runtime.getURL("welcome.html") });
  } else if (details.reason === "update") {
    try {
      const self = await chrome.management.getSelf?.();
      if (self?.installType === "development") {
        const KEY = "dev_welcome_last";
        const { [KEY]: last } = await chrome.storage.session.get(KEY);
        const today = new Date().toDateString();
        if (last !== today) {
          await chrome.storage.session.set({ [KEY]: today });
          chrome.tabs.create({ url: chrome.runtime.getURL("welcome.html?from=dev") });
        }
      }
    } catch {}
  }
});

/***** INIT *****/
chrome.runtime.onStartup?.addListener(() => {
  loadEnabled().catch(()=>{});                // << load switch state and set badge
  loadAllowlistFromCsv().catch(()=>{});
  loadUserAllowlist().catch(()=>{});
  rebuildDnrRules().catch(()=>{});
});
loadEnabled().catch(()=>{});                  // << also on extension load
loadAllowlistFromCsv().catch(()=>{});
loadUserAllowlist().catch(()=>{});
rebuildDnrRules().catch(()=>{});
