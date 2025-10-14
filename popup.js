function sendMessage(msg) {
  return new Promise((resolve) => chrome.runtime.sendMessage(msg, resolve));
}
function fmtProb(p) { return (Number(p) * 100).toFixed(1) + "%"; }
function fmtTs(ts) { try { return new Date(ts).toLocaleString(); } catch { return ts; } }

/* -------- LOGS -------- */
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

    const pill = document.createElement("div");
    pill.className = "pill " + (it.prediction ? "bad" : "good");
    pill.textContent = (it.prediction ? "UNSAFE" : "SAFE") + " • " + fmtProb(it.prob);

    row.appendChild(left);
    row.appendChild(pill);
    list.appendChild(row);
  }
}
async function refreshLogs() {
  const res = await sendMessage({ action: "get_history", limit: 200 });
  renderLogs(res?.ok ? (res.items || []) : []);
}

/* -------- BLOCKS -------- */
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
      loadBlocksPanel();
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
      loadBlocksPanel();
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

/* -------- INIT -------- */
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

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg?.action === "history_updated") refreshLogs();
    if (msg?.action === "blocks_updated") loadBlocksPanel();
    if (msg?.action === "block_history_updated") loadBlocksPanel();
  });

  refreshLogs();
});
