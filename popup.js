// popup.js
// — simplified explanations, live allowlist reason, forms wired
// — status pill aligned + feedback pill same size and under status
// — master ON/OFF switch wired to background

const ENABLED_KEY = "ext_enabled"; // (not used directly here but for clarity)

function sendMessage(msg) {
  return new Promise((resolve) => chrome.runtime.sendMessage(msg, resolve));
}
function fmtTs(ts) { try { return new Date(ts).toLocaleString(); } catch { return ts; } }

/* ---------------- helpers for domain/url input ---------------- */
function normalizeDomainOrUrlToUrl(input, fallbackScheme = "https:") {
  if (!input) return "";
  let s = String(input).trim();
  if (!s) return "";
  if (!/^https?:\/\//i.test(s)) {
    s = s.replace(/\s+/g, "");
    s = (fallbackScheme + "//" + s).replace(/:+\/\//, "://");
  }
  try {
    const u = new URL(s);
    if (!/^https?:$/.test(u.protocol)) u.protocol = "https:";
    return u.toString();
  } catch { return ""; }
}
function getBaseDomain(hostname) {
  try {
    const h = String(hostname || "").toLowerCase().trim();
    const parts = h.split(".").filter(Boolean);
    if (parts.length <= 2) return parts.join(".");
    return parts.slice(-2).join(".");
  } catch { return ""; }
}

/* ---------------- CLASSIFY (SAFE / SUSPECT / UNSAFE) ---------------- */
function classifyItem(it) {
  const pred = Number(it?.prediction || 0);
  const p = Number(it?.prob || 0);
  const isAllow = typeof it?.source === "string" && it.source.includes("allowlist-hard");

  if (isAllow && pred === 0) {
    return { label: "SAFE", cls: "good", level: "safe-allow" };
  }
  if (pred === 1) {
    if (p < 0.65) return { label: "SUSPECT", cls: "warn", level: "suspect" };
    return { label: "UNSAFE", cls: "bad", level: "unsafe" };
  }
  if (p >= 0.50) return { label: "SUSPECT", cls: "warn", level: "suspect" };
  return { label: "SAFE", cls: "good", level: "safe" };
}

/* ---------------- Explain (kept) ---------------- */
async function isAllowlistedNow(domainOrUrl) {
  let host = "";
  try {
    if (/^https?:\/\//i.test(domainOrUrl)) host = new URL(domainOrUrl).hostname;
    else host = String(domainOrUrl || "");
  } catch { host = String(domainOrUrl || ""); }
  if (!host) return { allowlisted:false, base:"", source:null };
  const res = await sendMessage({ action: "check_allowlisted_host", domain: host });
  if (res && res.ok) return { allowlisted: !!res.allowlisted, base: res.base || "", source: res.source || null };
  return { allowlisted:false, base:"", source:null };
}
function explainDecision(it, allowInfo) {
  const domain = it?.domain || (it?.url ? (new URL(it.url).hostname) : "");
  const url = it?.url || "";
  if (allowInfo?.allowlisted) {
    const srcText = allowInfo.source === "user"
      ? "อยู่ใน Allowlist ที่คุณเพิ่มไว้"
      : "อยู่ใน Allowlist มาตรฐานของระบบ (CSV)";
    return {
      title: "SAFE (ปลอดภัยเพราะอยู่ใน Allowlist)",
      bullets: [
        `โดเมนนี้${srcText} จึงผ่านการเตือนเบื้องต้น`,
        "ข้อควรทราบ: Allowlist จะยอมให้เข้าได้แม้โมเดลจะไม่มั่นใจ ควรใช้กับโดเมนที่คุณไว้ใจจริง ๆ เท่านั้น",
        `โดเมน: ${allowInfo.base || domain}`
      ]
    };
  }
  const pred = Number(it?.prediction || 0);
  const p = Number(it?.prob || 0);
  if (pred === 1) {
    if (p < 0.65) {
      return {
        title: "SUSPECT (น่าสงสัย/ใกล้เส้นแบ่ง)",
        bullets: [
          "โมเดลให้คะแนนใกล้เส้นแบ่ง อาจมีความเสี่ยงแต่ยังไม่ชัดเจน",
          "แนะนำ: ตรวจชื่อโดเมนให้แน่ใจ และเลี่ยงกรอกข้อมูลสำคัญ",
          `ลิงก์ที่ตรวจ: ${url}`
        ]
      };
    }
    return {
      title: "UNSAFE (เสี่ยงสูงจากรูปแบบที่คล้ายฟิชชิง)",
      bullets: [
        "รูปแบบของลิงก์นี้คล้ายกับตัวอย่างฟิชชิงจำนวนมากที่โมเดลเรียนรู้มา",
        "แนะนำ: อย่าใส่รหัสผ่าน/เลขบัตร/OTP บนหน้านี้ หากไม่แน่ใจให้ย้อนกลับหรือปิดแท็บ",
        `ลิงก์ที่ตรวจ: ${url}`
      ]
    };
  }
  if (p >= 0.50) {
    return {
      title: "SUSPECT (น่าสงสัย/ใกล้เส้นแบ่ง)",
      bullets: [
        "ยังไม่พบสัญญาณชัดเจน แต่โมเดลประเมินใกล้เส้นแบ่ง",
        "แนะนำ: ตรวจสอบความน่าเชื่อถือของเว็บก่อนกรอกข้อมูลสำคัญ",
        `โดเมน: ${domain}`
      ]
    };
  }
  return {
    title: "SAFE (ไม่พบสัญญาณเสี่ยงเด่นชัด)",
    bullets: [
      "ไม่พบรูปแบบที่เข้าข่ายฟิชชิงจากเกณฑ์เบื้องต้น",
      "อย่างไรก็ดี ระบบนี้ใช้ Machine Learning อาจคลาดเคลื่อนได้ ควรระวังเมื่อกรอกข้อมูลสำคัญ",
      `โดเมน: ${domain}`
    ]
  };
}
async function showExplainModal(it) {
  const domainOrUrl = it?.domain || it?.url || "";
  const allowInfo = await isAllowlistedNow(domainOrUrl);
  const ex = explainDecision(it, allowInfo);

  const overlay = document.createElement("div");
  overlay.style.cssText = `
    position:fixed; inset:0; background:rgba(0,0,0,.35); display:flex;
    align-items:center; justify-content:center; z-index:99999; padding:16px;
  `;
  const box = document.createElement("div");
  box.style.cssText = `
    background:#fff; color:#111; width: min(320px, 94vw); border-radius:12px;
    border:1px solid #e5e7eb; box-shadow: 0 10px 30px rgba(0,0,0,.15);
    padding:14px 14px 10px; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
  `;
  const hd = document.createElement("div");
  hd.style.cssText = "display:flex; align-items:center; justify-content:space-between; gap:8px; margin-bottom:6px;";
  const h = document.createElement("div");
  h.textContent = "คำอธิบายการตัดสินใจ";
  h.style.cssText = "font-weight:700; font-size:14px;";
  const x = document.createElement("button");
  x.textContent = "×";
  x.style.cssText = "border:none;background:transparent;font-size:18px;line-height:1;cursor:pointer;";
  x.addEventListener("click", () => overlay.remove());
  hd.appendChild(h); hd.appendChild(x);

  const title = document.createElement("div");
  title.textContent = ex.title;
  title.style.cssText = "font-weight:700; font-size:13px; margin:6px 0;";

  const ul = document.createElement("ul");
  ul.style.cssText = "padding-left:18px; margin:8px 0;";
  for (const b of ex.bullets) {
    const li = document.createElement("li");
    li.textContent = b;
    li.style.cssText = "font-size:12px; line-height:1.45;";
    ul.appendChild(li);
  }

  const actions = document.createElement("div");
  actions.style.cssText = "display:flex; gap:8px; margin-top:8px;";
  const fbBtn = document.createElement("button");
  fbBtn.textContent = "ส่งฟีดแบ็ก";
  fbBtn.style.cssText = "border:1px solid #ddd; background:#fff; border-radius:8px; padding:6px 8px; cursor:pointer;";
  fbBtn.addEventListener("click", () => {
    openFeedbackPage(it);
  });
  actions.appendChild(fbBtn);

  const note = document.createElement("div");
  note.textContent = "หมายเหตุ: ใช้โมเดล ML ช่วยตัดสินใจ อาจคลาดเคลื่อนได้ ใช้วิจารณญาณก่อนกรอกข้อมูลสำคัญ";
  note.style.cssText = "font-size:11px;color:#666;margin-top:6px;";

  box.appendChild(hd);
  box.appendChild(title);
  box.appendChild(ul);
  box.appendChild(actions);
  box.appendChild(note);
  overlay.appendChild(box);
  document.body.appendChild(overlay);
}

/* ---------------- open feedback page ---------------- */
function openFeedbackPage(it) {
  const cls = classifyItem(it);
  const q = new URLSearchParams({
    url: it.url || "",
    domain: it.domain || "",
    model_label: cls.label || ""
  });
  const page = chrome.runtime.getURL(`feedback.html?${q.toString()}`);
  chrome.tabs.create({ url: page });
}

/* ---------------- LOGS PANEL ---------------- */
function renderLogs(items) {
  const list = document.getElementById("list");
  const meta = document.getElementById("meta");
  list.innerHTML = "";
  meta.textContent = `ประวัติ: ${items.length} รายการ (ล่าสุดอยู่บนสุด)`;

  if (!items.length) {
    list.innerHTML = `<div class="empty">ยังไม่มีประวัติการตรวจ</div>`;
    return;
  }
  for (const it of items) {
    const row = document.createElement("div");
    row.className = "row";

    const left = document.createElement("div");
    const url = document.createElement("div");
    url.className = "url";
    url.textContent = it.url;

    const sub = document.createElement("div");
    sub.className = "sub";
    sub.textContent = `${it.domain} • ${fmtTs(it.ts)} • ${it.source}`;

    left.appendChild(url);
    left.appendChild(sub);

    const cls = classifyItem(it);

    // Right column: status pill (top) + feedback pill (bottom)
    const pillWrap = document.createElement("div");
    pillWrap.className = "pillcol";

    const pill = document.createElement("div");
    pill.className = "pill " + (cls.cls === "warn" ? "warn" : cls.cls);
    pill.textContent = cls.label;
    pill.title = "กดเพื่อดูเหตุผลแบบย่อ";
    pill.addEventListener("click", () => { showExplainModal(it); });

    const fbBtn = document.createElement("button");
    fbBtn.textContent = "ฟีดแบ็ก";
    fbBtn.className = "pill-fb " + (cls.cls === "bad" ? "bad" : (cls.cls === "good" ? "good" : "warn"));
    fbBtn.addEventListener("click", () => openFeedbackPage(it));

    pillWrap.appendChild(pill);
    pillWrap.appendChild(fbBtn);

    row.appendChild(left);
    row.appendChild(pillWrap);
    list.appendChild(row);
  }
}
async function refreshLogs() {
  const res = await sendMessage({ action: "get_history", limit: 200 });
  renderLogs(res?.ok ? (res.items || []) : []);
}

/* ---------------- BLOCKS PANEL (เดิม + wire ฟอร์ม) ---------------- */
function renderBlockSets(domains, urls) {
  const dEl = document.getElementById("block-domains");
  const uEl = document.getElementById("block-urls");
  dEl.innerHTML = ""; uEl.innerHTML = "";

  if (!domains.length) dEl.innerHTML = `<div class="empty">-</div>`;
  if (!urls.length) uEl.innerHTML = `<div class="empty">-</div>`;

  for (const d of domains) {
    const line = document.createElement("div");
    line.className = "line";
    line.innerHTML = `<span>${d}</span>`;
    const btn = document.createElement("button");
    btn.textContent = "ยกเลิก";
    btn.addEventListener("click", async () => {
      await sendMessage({ action: "remove_block_domain", domain: d });
      await loadBlocksPanel();
    });
    line.appendChild(btn);
    dEl.appendChild(line);
  }
  for (const u of urls) {
    const line = document.createElement("div");
    line.className = "line";
    line.innerHTML = `<span>${u}</span>`;
    const btn = document.createElement("button");
    btn.textContent = "ยกเลิก";
    btn.addEventListener("click", async () => {
      await sendMessage({ action: "remove_block_url", url: u });
      await loadBlocksPanel();
    });
    line.appendChild(btn);
    uEl.appendChild(line);
  }
}
function renderBlockHistory(items) {
  const root = document.getElementById("block-history");
  root.innerHTML = "";
  if (!items.length) { root.innerHTML = `<div class="empty">-</div>`; return; }
  for (const it of items) {
    const div = document.createElement("div");
    div.className = "row";
    const left = document.createElement("div");
    left.innerHTML = `<div class="url">${it.url || it.value}</div><div class="sub">${it.type}:${it.value} • ${fmtTs(it.ts)} • ${it.who||"-"}</div>`;
    div.appendChild(left);
    root.appendChild(div);
  }
}
async function loadBlocksPanel() {
  const sets = await sendMessage({ action: "get_blocks" });
  if (sets?.ok) renderBlockSets(sets.domains || [], sets.urls || []);
  const hist = await sendMessage({ action: "get_block_history", limit: 200 });
  if (hist?.ok) renderBlockHistory(hist.items || []);
}

/* ---------------- Allowlist UI ---------------- */
function renderAllowlist(domains) {
  const root = document.getElementById("allowlist-root");
  if (!root) return;
  root.innerHTML = "";

  if (!domains || !domains.length) {
    root.innerHTML = `<div class="empty">ยังไม่มีโดเมนใน Allowlist ของคุณ</div>`;
    return;
  }

  for (const d of domains) {
    const line = document.createElement("div");
    line.className = "line";
    line.innerHTML = `<span>${d}</span>`;
    const btn = document.createElement("button");
    btn.textContent = "ลบออก";
    btn.addEventListener("click", async () => {
      await sendMessage({ action: "allow_remove_domain", domain: d });
      const res = await sendMessage({ action: "get_allowlist" });
      renderAllowlist(res?.ok ? (res.domains || []) : []);
    });
    line.appendChild(btn);
    root.appendChild(line);
  }
}
async function refreshAllowlist() {
  const res = await sendMessage({ action: "get_allowlist" });
  renderAllowlist(res?.ok ? (res.domains || []) : []);
}

/* ---------------- Master ON/OFF switch ---------------- */
function bindMasterSwitch() {
  const sw = document.getElementById("toggle-enabled");
  if (!sw) return;

  sendMessage({ action: "get_enabled" }).then((res) => {
    sw.checked = !!res?.enabled;
  });

  sw.addEventListener("change", async () => {
    const enabled = !!sw.checked;
    await sendMessage({ action: "set_enabled", enabled });
  
    // อัปเดต badge ให้ตรงกับสถานะทันทีที่ผู้ใช้สลับ
    if (!enabled) {
      chrome.action.setBadgeText({ text: "OFF" });
      chrome.action.setBadgeBackgroundColor({ color: "#9aa0a6" });
    } else {
      // เปิดใช้งาน: เคลียร์ badge (background จะใส่เตือนให้ถ้าตรวจพบความเสี่ยง)
      chrome.action.setBadgeText({ text: "" });
      chrome.action.setBadgeBackgroundColor({ color: "#16a34a" });
    }
  });
  
}

/* ---------------- INIT ---------------- */
document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("btn-check").addEventListener("click", async () => {
    const btn = document.getElementById("btn-check");
    const old = btn.textContent;
    btn.textContent = "กำลังตรวจ...";
    btn.disabled = true;
    try {
      const res = await sendMessage({ action: "manual_check_active_tab" });
      if (!res?.ok) alert("ตรวจสอบไม่สำเร็จ: " + (res?.error || "unknown error"));
      await refreshLogs();
    } finally {
      btn.textContent = old;
      btn.disabled = false;
    }
  });

  document.getElementById("btn-clear").addEventListener("click", async () => {
    if (!confirm("ล้างประวัติทั้งหมด?")) return;
    await sendMessage({ action: "clear_history" });
    await refreshLogs();
  });

  const tabLogs = document.getElementById("tab-logs");
  const tabBlocks = document.getElementById("tab-blocks");
  const panelLogs = document.getElementById("panel-logs");
  const panelBlocks = document.getElementById("panel-blocks");

  function activate(which) {
    if (which === "logs") {
      tabLogs.classList.add("active"); tabBlocks.classList.remove("active");
      panelLogs.style.display = ""; panelBlocks.style.display = "none";
    } else {
      tabBlocks.classList.add("active"); tabLogs.classList.remove("active");
      panelBlocks.style.display = ""; panelLogs.style.display = "none";
      refreshAllowlist();
    }
  }
  tabLogs.addEventListener("click", () => activate("logs"));
  tabBlocks.addEventListener("click", () => { activate("blocks"); loadBlocksPanel(); });

  document.getElementById("btn-refresh-blocks").addEventListener("click", loadBlocksPanel);
  document.getElementById("btn-clear-block-history").addEventListener("click", async () => {
    if (!confirm("ล้างประวัติการบล็อคทั้งหมด?")) return;
    await sendMessage({ action: "clear_block_history" });
    await loadBlocksPanel();
  });

  // Allowlist forms
  const allowInput = document.getElementById("allow-domain-input");
  const allowBtn = document.getElementById("btn-allow-add");
  if (allowBtn && allowInput) {
    allowBtn.addEventListener("click", async () => {
      const urlStr = normalizeDomainOrUrlToUrl(allowInput.value, "https:");
      if (!urlStr) { alert("กรุณากรอกโดเมนหรือ URL ให้ถูกต้อง"); return; }
      const host = new URL(urlStr).hostname;
      const base = getBaseDomain(host);
      if (!base) { alert("ไม่สามารถอ่านโดเมนได้"); return; }
      await sendMessage({ action: "allow_add_domain", domain: base });
      allowInput.value = "";
      await refreshAllowlist();
    });
  }

  const blockDomainInput = document.getElementById("block-domain-input");
  const blockDomainBtn = document.getElementById("btn-block-domain-add");
  if (blockDomainBtn && blockDomainInput) {
    blockDomainBtn.addEventListener("click", async () => {
      const urlStr = normalizeDomainOrUrlToUrl(blockDomainInput.value, "https:");
      if (!urlStr) { alert("กรุณากรอกโดเมนให้ถูกต้อง"); return; }
      await sendMessage({ action: "block_add_domain", url: urlStr, reason: "manual" });
      blockDomainInput.value = "";
      await loadBlocksPanel();
    });
  }

  const blockUrlInput = document.getElementById("block-url-input");
  const blockUrlBtn = document.getElementById("btn-block-url-add");
  if (blockUrlBtn && blockUrlInput) {
    blockUrlBtn.addEventListener("click", async () => {
      const urlStr = normalizeDomainOrUrlToUrl(blockUrlInput.value, "https:");
      if (!urlStr) { alert("กรุณากรอก URL ให้ถูกต้อง"); return; }
      await sendMessage({ action: "block_add_url", url: urlStr, reason: "manual" });
      blockUrlInput.value = "";
      await loadBlocksPanel();
    });
  }

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg?.action === "history_updated") refreshLogs();
    if (msg?.action === "blocks_updated") loadBlocksPanel();
    if (msg?.action === "block_history_updated") loadBlocksPanel();
    if (msg?.action === "allowlist_updated") refreshAllowlist();
    if (msg?.action === "feedback_updated") {/* no-op */}
  });

  bindMasterSwitch();
  refreshLogs();
});
