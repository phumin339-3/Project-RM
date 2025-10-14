function sendMessage(msg) {
  return new Promise((resolve) => chrome.runtime.sendMessage(msg, resolve));
}
function fmtProb(p) { return (Number(p) * 100).toFixed(1) + "%"; }
function fmtTs(ts) { try { return new Date(ts).toLocaleString(); } catch { return ts; } }

function render(items) {
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

async function refresh() {
  const res = await sendMessage({ action: "get_history", limit: 100 });
  render(res?.ok ? (res.items || []) : []);
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("btn-check").addEventListener("click", async () => {
    const btn = document.getElementById("btn-check");
    const old = btn.textContent;
    btn.textContent = "กำลังตรวจ...";
    btn.disabled = true;
    try {
      const res = await sendMessage({ action: "manual_check_active_tab" });
      if (!res?.ok) alert("ตรวจสอบไม่สำเร็จ: " + (res?.error || "unknown error"));
      await refresh();
    } finally {
      btn.textContent = old;
      btn.disabled = false;
    }
  });

  document.getElementById("btn-clear").addEventListener("click", async () => {
    if (!confirm("ล้างประวัติทั้งหมด?")) return;
    await sendMessage({ action: "clear_history" });
    await refresh();
  });

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg?.action === "history_updated") refresh();
  });

  refresh();
});
