// background.js — ประวัติ + เช็คอัตโนมัติ + allowlist จาก CSV + handshake offscreen

const HISTORY_KEY = "check_history";
const HISTORY_LIMIT = 300;
const AUTO_CHECK = true;
const MIN_RECHECK_MS = 5 * 60 * 1000;
const VALID_SCHEMES = new Set(["http:", "https:"]);

const lastCheckedAt = new Map(); // url -> ms
let offscreenReadyWaiter = null;

/* ========= ALLOWLIST (โหลดจาก CSV) ========= */
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
      if (line.startsWith("#")) continue;

      if (!headerHandled && /^domain(?:,|$)/i.test(line)) { // ข้าม header "domain"
        headerHandled = true; continue;
      }
      headerHandled = true;

      let domain = line;
      const parts = line.split(",");
      if (parts.length >= 2) domain = parts[1];
      domain = String(domain).trim().replace(/^"+|"+$/g, "");
      if (!domain) continue;

      set.add(normalizeDomainToETLD1(domain));
    }
    ALLOWLIST_SET = set;
    console.log("✅ Allowlist loaded:", ALLOWLIST_SET.size, "domains");
    return ALLOWLIST_SET;
  })();

  return allowlistReadyPromise;
}

function isAllowedHostBySet(hostname) {
  if (!hostname) return false;
  if (!ALLOWLIST_SET) return false;
  const host = String(hostname).toLowerCase();
  const base = normalizeDomainToETLD1(host);
  if (ALLOWLIST_SET.has(base)) return true;
  return (host === base) || host.endsWith("." + base);
}

/* -------- offscreen handshake -------- */
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
  } catch (_) {}
  await chrome.offscreen.createDocument({
    url: chrome.runtime.getURL("offscreen.html"),
    reasons: [chrome.offscreen.Reason.BLOBS],
    justification: "Run ONNX (WASM) for URL safety scoring"
  });
  await waitForOffscreenReady().catch(() => {});
}

/* -------- history helpers -------- */
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
function nowISO() { return new Date().toISOString(); }
function safeDomain(url) { try { return new URL(url).hostname; } catch { return ""; } }
function shouldAutoCheck(url) {
  try { if (!VALID_SCHEMES.has(new URL(url).protocol)) return false; } catch { return false; }
  const last = lastCheckedAt.get(url) || 0;
  return (Date.now() - last) > MIN_RECHECK_MS;
}

/* -------- core check (allowlist → model) -------- */
async function checkUrlSafety(url) {
  const host = safeDomain(url);

  // โหลด allowlist ครั้งแรก
  try { await loadAllowlistFromCsv(); } catch {}

  // Hard allow: ถ้าอยู่ใน allowlist → SAFE ทันที
  if (isAllowedHostBySet(host)) {
    return { prediction: 0, unsafe_probability: 0.001, reason: "allowlist-hard" };
  }

  // อื่นๆ → ส่งเข้าโมเดล
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

/* -------- auto check on navigation complete -------- */
if (AUTO_CHECK) {
  chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    try {
      if (changeInfo.status !== "complete") return;
      const url = tab?.url || "";
      if (!shouldAutoCheck(url)) return;

      lastCheckedAt.set(url, Date.now());

      const { prediction, unsafe_probability, reason } = await checkUrlSafety(url);
      const item = {
        url,
        domain: safeDomain(url),
        prob: Number(unsafe_probability || 0),
        prediction: Number(prediction || 0), // 1=UNSAFE, 0=SAFE
        ts: nowISO(),
        source: reason ? `auto:${reason}` : "auto"
      };
      await appendHistory(item);

      chrome.action.setBadgeText({ text: item.prediction ? "⚠" : "", tabId });
      chrome.action.setBadgeBackgroundColor({
        color: item.prediction ? "#d9534f" : "#2ecc71", tabId
      });
    } catch (e) {
      console.warn("auto-check error:", e);
    }
  });
}

/* -------- popup API -------- */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
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
    (async () => {
      await saveHistory([]);
      lastCheckedAt.clear(); // reset throttle
      sendResponse({ ok: true });
    })();
    return true;
  }

  if (msg?.action === "manual_check_active_tab") {
    (async () => {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab?.url) return sendResponse({ ok: false, error: "No active tab URL" });

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

        chrome.action.setBadgeText({ text: item.prediction ? "⚠" : "" , tabId: tab.id });
        chrome.action.setBadgeBackgroundColor({
          color: item.prediction ? "#d9534f" : "#2ecc71", tabId: tab.id
        });

        sendResponse({ ok: true, item });
      } catch (e) {
        sendResponse({ ok: false, error: String(e) });
      }
    })();
    return true;
  }

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

  // ไม่มี default sendResponse เพื่อไม่ชนกับข้อความที่ให้ offscreen ตอบ
});

/* -------- init -------- */
chrome.runtime.onInstalled.addListener(() => {
  chrome.action.setBadgeText({ text: "" });
  loadAllowlistFromCsv().catch(()=>{});
});
chrome.runtime.onStartup?.addListener(() => { loadAllowlistFromCsv().catch(()=>{}); });
loadAllowlistFromCsv().catch(()=>{});
