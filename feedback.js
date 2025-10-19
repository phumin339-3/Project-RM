// feedback.js — ฟอร์มฟีดแบ็ก (ไม่บันทึกอัตโนมัติ; Export เฉพาะหมวดที่เลือก)

(function () {
  const $ = (s) => document.querySelector(s);

  // ---- Read query ----
  const params = new URLSearchParams(location.search);
  const url = params.get("url") || "";
  const domain = params.get("domain") || (url ? safeHost(url) : "");
  const modelLabel = (params.get("model_label") || "-").toUpperCase();

  // ---- Init header fields ----
  $("#url").value = url;
  $("#domain").value = domain;
  applyStatusPill(modelLabel);

  // ---- Segments ----
  const segNot = $("#segNot");
  const segIs  = $("#segIs");
  const groupNot = $("#group-not");
  const groupIs  = $("#group-is");

  let currentMode = "not_phishing"; // default

  segNot.addEventListener("click", () => setMode("not_phishing"));
  segIs.addEventListener("click",  () => setMode("is_phishing"));
  setMode(currentMode);

  // ---- Back / Export ----
  $("#btnBack").addEventListener("click", () => {
    if (history.length > 1) history.back();
    else window.close();
  });

  $("#btnExport").addEventListener("click", () => {
    const payload = buildPayload();
    const pretty = JSON.stringify(payload, null, 2);
    const blob = new Blob([pretty], { type: "application/json" });
    const a = document.createElement("a");
    const ts = new Date().toISOString().replace(/[:.]/g, "-");
    a.href = URL.createObjectURL(blob);
    a.download = `feedback_${payload.user_claim}_${ts}.json`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      URL.revokeObjectURL(a.href);
      a.remove();
    }, 500);
  });

  // ===== helpers =====
  function safeHost(u){
    try{ return new URL(u).hostname; }catch{ return ""; }
  }

  function applyStatusPill(label){
    const pill = $("#statusPill");
    pill.textContent = label;
    pill.className = "pill"; // reset
    if (label === "SAFE") pill.classList.add("pill-good");
    else if (label === "SUSPECT") pill.classList.add("pill-warn");
    else if (label === "UNSAFE") pill.classList.add("pill-bad");
  }

  function setMode(mode){
    currentMode = mode;
    if (mode === "not_phishing"){
      segNot.classList.add("active"); segIs.classList.remove("active");
      groupNot.style.display = "";   groupIs.style.display = "none";
    }else{
      segIs.classList.add("active");  segNot.classList.remove("active");
      groupIs.style.display = "";     groupNot.style.display = "none";
    }
  }

  function getFlagsFrom(container){
    return Array.from(container.querySelectorAll('input[type="checkbox"]:checked'))
      .map(ch => ch.value);
  }

  function buildPayload(){
    const ts = new Date().toISOString();
    if (currentMode === "not_phishing"){
      return {
        url,
        domain,
        model_label: modelLabel || "-",
        user_claim: "not_phishing",
        flags: getFlagsFrom(groupNot),
        note: $("#note").value || "",
        ts
      };
    }else{
      return {
        url,
        domain,
        model_label: modelLabel || "-",
        user_claim: "is_phishing",
        flags: getFlagsFrom(groupIs),
        note: $("#note").value || "",
        ts
      };
    }
  }
})();
