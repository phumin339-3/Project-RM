// feedback.js — ฟอร์มฟีดแบ็ก (ไม่บันทึกอัตโนมัติ; Export เฉพาะหมวดที่เลือก)

(function () {
  const $ = (s) => document.querySelector(s);

  const emailFallback = document.getElementById("emailFallback");
  const manualEmail = document.getElementById("manualEmail");


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

  const allowEmail = document.getElementById("allowEmail");
  const emailPreview = document.getElementById("emailPreview");
  const emailText = document.getElementById("emailText");

  allowEmail.addEventListener("change", () => {
    if (!allowEmail.checked) {
      emailPreview.style.display = "none";
      emailFallback.style.display = "none";
      manualEmail.value = "";
      return;
    }
  
    chrome.runtime.sendMessage(
      { action: "get_user_email_preview" },
      (res) => {
        if (res?.email) {
          emailText.textContent = maskEmail(res.email);
          emailPreview.style.display = "";
          emailFallback.style.display = "none";
        } else {
          emailText.textContent = "(ไม่พบอีเมลจาก Google)";
          emailPreview.style.display = "";
          emailFallback.style.display = "";
        }
      }
    );
  });
  


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
  
    const email =
      emailText.textContent && !emailText.textContent.includes("ไม่พบ")
        ? emailText.textContent
        : manualEmail.value || "";
  
    chrome.runtime.sendMessage(
      {
        action: "feedback_add_and_send",
        ...payload,
        allow_email: allowEmail.checked,
        email: email
      },
      (res) => {
        if (res?.ok) {
          alert("ส่งฟีดแบ็กเรียบร้อยแล้ว");
          window.close();
        } else {
          alert("ส่งฟีดแบ็กไม่สำเร็จ");
          console.error(res);
        }
      }
    );
  });
  
  
  
  function maskEmail(email) {
    if (!email || !email.includes("@")) return "";
    const [name, domain] = email.split("@");
    return name.slice(0, 3) + "***@" + domain;
  }
  
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
