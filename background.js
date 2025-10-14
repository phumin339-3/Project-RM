// background.js — history + allowlist + DNR block (requestDomains/regex) + interstitial + notifications + offscreen + smart_back

/***** CONFIG *****/
const HISTORY_KEY = "check_history";
const HISTORY_LIMIT = 300;

const BLOCK_DOMAIN_KEY = "block_domain_set";
const BLOCK_URL_KEY    = "block_url_set";
const BLOCK_HISTORY_KEY= "block_history";

const AUTO_CHECK = true;
const MIN_RECHECK_MS = 5 * 60 * 1000;
const VALID_SCHEMES = new Set(["http:", "https:"]);
const BYPASS_MINUTES_DEFAULT = 5;

const lastCheckedAt = new Map();       // url -> ms
let offscreenReadyWaiter = null;

/***** ALLOWLIST (CSV) *****/
const ALLOWLIST_CSV_PATH = "data/allowlist.csv";
let ALLOWLIST_SET = null;
let allowlistReadyPromise = null;

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
    console.log("✅ Allowlist loaded:", ALLOWLIST_SET.size);
    return ALLOWLIST_SET;
  })();
  return allowlistReadyPromise;
}
function isAllowedHostBySet(hostname) {
  if (!hostname || !ALLOWLIST_SET) return false;
  const base = normalizeDomainToETLD1(hostname);
  return ALLOWLIST_SET.has(base);
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

/***** STORAGE: history + blocklists *****/
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
  await rebuildDnrRules();                                       // อัปเดตกฎ DNR ทุกครั้งที่มีการเปลี่ยนบล็อค
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

// บล็อค URL ตรงตัว → ใช้ regexFilter+regexSubstitution เพื่อส่ง URL เดิมไปหน้าเตือน (url=\0)
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

// บล็อคโดเมน (รวมซับโดเมน) → ใช้ requestDomains + queryTransform ส่งเหตุผล/โดเมนเข้า warning.html
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
      requestDomains: [domain],               // << สำคัญ! ครอบคลุมซับโดเมน
      resourceTypes: ["main_frame"]
    }
  };
}

async function rebuildDnrRules() {
  const { domains, urls } = await loadBlocks();
  const rules = [];
  let nextId = DNR_RULE_ID_START;

  // URL รายตัว
  for (const u of urls) {
    rules.push(ruleForBlockedUrl(nextId++, u));
    if (rules.length >= DNR_MAX_RULES) break;
  }

  // โดเมน
  for (const d of domains) {
    rules.push(ruleForBlockedDomain(nextId++, d));
    if (rules.length >= DNR_MAX_RULES) break;
  }

  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const toRemove = existing.map(r => r.id);

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: toRemove,
    addRules: rules
  });

  console.log("✅ DNR rules updated:", rules.length);
}

/***** MODEL CHECK + INTERSTITIAL (เฉพาะไม่โดน DNR กันไว้) *****/
async function checkUrlSafety(url) {
  const host = safeDomain(url);
  try { await loadAllowlistFromCsv(); } catch {}

  if (isAllowedHostBySet(host)) {
    return { prediction: 0, unsafe_probability: 0.001, reason: "allowlist-hard" };
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

/***** AUTO CHECK (เร็วขึ้น: ตอน loading) *****/
if (AUTO_CHECK) {
  chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    try {
      if (changeInfo.status !== "loading") return;
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

/***** SMART BACK: ย้อนแบบเมาส์ปุ่ม 5 (ถอยจนพ้น warning/โดเมนที่บล็อค/โดเมนต้นเหตุ) *****/
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
async function stillBlockedOrWarning(url, avoidBase) {
  if (!url) return true;
  if (isWarningUrl(url)) return true;
  // เลี่ยงโดเมนที่เป็นต้นเหตุ แม้จะยังไม่ถูกบล็อก
  try {
    const host = safeDomain(url);
    const base = normalizeDomainToETLD1(host);
    if (avoidBase && base === avoidBase) return true;
  } catch {}
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
async function smartBack(tabId, maxSteps = 15, avoidBase) {
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

    const bad = await stillBlockedOrWarning(curUrl, avoidBase);
    if (!bad) return { ok:true, url: curUrl, steps };
  }

  // หมดทาง: ไปหน้า blank กันวนลูป
  try { await chrome.tabs.update(tabId, { url: "about:blank" }); } catch {}
  return { ok:false, error:"exhausted", steps };
}

/***** POPUP & WARNING APIs (incl. smart_back) *****/
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // LOGS
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

  // BLOCKS
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

  // WARNING page actions
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

  // SMART BACK (ย้อนหลายสเต็ป)
  if (msg?.action === "smart_back") {
    (async () => {
      const tabId = typeof msg.tabId === "number" ? msg.tabId : undefined;
      const maxSteps = Number(msg.maxSteps || 15);

      // แปลง msg.avoid เป็น eTLD+1 เพื่อใช้เทียบโดเมน
      let avoidBase = "";
      try {
        if (msg.avoid) {
          const maybeDomain = String(msg.avoid).trim();
          const host = /^[\w.-]+$/.test(maybeDomain) ? maybeDomain : safeDomain(maybeDomain);
          avoidBase = normalizeDomainToETLD1(host);
        }
      } catch {}

      const result = await smartBack(tabId, maxSteps, avoidBase);
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

  // preload model (optional)
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
});

/***** INIT *****/
chrome.runtime.onInstalled.addListener(() => {
  chrome.action.setBadgeText({ text: "" });
  loadAllowlistFromCsv().catch(()=>{});
  rebuildDnrRules().catch(()=>{});
});
chrome.runtime.onStartup?.addListener(() => {
  loadAllowlistFromCsv().catch(()=>{});
  rebuildDnrRules().catch(()=>{});
});
loadAllowlistFromCsv().catch(()=>{});
rebuildDnrRules().catch(()=>{});
