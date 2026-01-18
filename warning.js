// warning.js — หน้าเตือน + ปุ่มย้อนแบบ "เมาส์ปุ่ม 5" (ให้ BG กดย้อนจนพ้นหน้าเตือน/โดเมนที่บล็อค)
(function () {
    // ---------- helpers ----------
    const $ = id => document.getElementById(id);
    const hasRuntime = () =>
      typeof chrome !== "undefined" && chrome?.runtime?.sendMessage;
  
    function q(name) {
      try { return new URL(location.href).searchParams.get(name) || ""; }
      catch { return ""; }
    }
    function sendMsg(msg) {
      if (!hasRuntime()) return Promise.resolve({ ok:false, error:"no-runtime" });
      return new Promise(res => {
        try { chrome.runtime.sendMessage(msg, r => res(r)); }
        catch (e) { res({ ok:false, error:String(e) }); }
      });
    }
  
    document.addEventListener("DOMContentLoaded", () => {
      // ---------- read params ----------
      let originalUrl = q("url");                 // จาก DNR (regexSubstitution: \0) หรือ auto-check model
      const why = q("why") || "detected-unsafe";
      const tabId = /^\d+$/.test(q("tabId")) ? Number(q("tabId")) : undefined;
      const blockedDomain = q("domain");          // จาก DNR requestDomains กรณีบล็อคโดเมน
  
      if (!originalUrl && document.referrer) {
        try { originalUrl = new URL(document.referrer).href; } catch {}
      }
  
      // ---------- render ----------
      $("targetUrl") && ($("targetUrl").textContent = originalUrl || "(ไม่ทราบ URL)");
      const extra = blockedDomain ? ` (โดเมนที่ถูกบล็อค: ${blockedDomain})` : "";
      $("reason") && ($("reason").textContent = "เหตุผล: " + (why || "-") + extra);
      $("tabNote") && ($("tabNote").textContent = tabId != null ? ("แท็บ #" + tabId) : "");
  
      // แจ้งเตือนเมื่อเหตุผลเป็น blocked:*
      if (/^blocked:/.test(why)) {
        sendMsg({ action: "notify_blocked", url: originalUrl || blockedDomain, why }).catch(()=>{});
      }
  
      // ---------- ปุ่มย้อน: ให้ BG ทำ smart_back (วน goBack จนพ้น warning/โดเมนบล็อค/โดเมนต้นเหตุ) ----------
      $("go-back")?.addEventListener("click", async (ev) => {
        ev.preventDefault();
        const btn = ev.currentTarget; btn.disabled = true;
        try {
          // บอก BG ให้ "เลี่ยง" โดเมน/URL ที่ทำให้มาเจอหน้าเตือน แม้ยังไม่ได้อยู่ใน block list
          const avoid = blockedDomain || originalUrl || "";
          await sendMsg({ action: "smart_back", tabId, maxSteps: 15, avoid });
          // BG จะจัดการนำทางแท็บให้จนพ้นเงื่อนไขเอง
        } finally { btn.disabled = false; }
      });
  
      // ---------- ปุ่มยืนยันเข้าเว็บ (เฉพาะ model-unsafe; blocked:* จะถูก DNR ตัดอยู่ดี) ----------
      $("proceed-once")?.addEventListener("click", async (ev) => {
        ev.preventDefault();
        if (!originalUrl) return;
        const btn = ev.currentTarget; btn.disabled = true;
        try {
          await sendMsg({ action: "bypass_once", url: originalUrl, tabId, minutes: 5 });
          if (hasRuntime() && tabId != null && chrome.tabs?.update) {
            chrome.tabs.update(tabId, { url: originalUrl });
          } else {
            location.href = originalUrl;
          }
        } finally { btn.disabled = false; }
      });
  
      // ---------- ปุ่มบล็อคโดเมน ----------
      $("block-domain")?.addEventListener("click", async (ev) => {
        ev.preventDefault();
        const btn = ev.currentTarget; btn.disabled = true;
        try {
          const src = originalUrl || (blockedDomain ? `https://${blockedDomain}` : "");
          if (src) await sendMsg({ action: "block_add_domain", url: src, reason: "manual" });
          await sendMsg({ action: "smart_back", tabId, maxSteps: 15, avoid: blockedDomain || originalUrl || "" });
        } finally { btn.disabled = false; }
      });
  
      // ---------- ปุ่มบล็อค URL ----------
      $("block-url")?.addEventListener("click", async (ev) => {
        ev.preventDefault();
        const btn = ev.currentTarget; btn.disabled = true;
        try {
          if (originalUrl) await sendMsg({ action: "block_add_url", url: originalUrl, reason: "manual" });
          await sendMsg({ action: "smart_back", tabId, maxSteps: 15, avoid: blockedDomain || originalUrl || "" });
        } finally { btn.disabled = false; }
      });
    });
  })();