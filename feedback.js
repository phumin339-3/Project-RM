// feedback.js — ฟอร์มฟีดแบ็ก (clean version, manual email only)

(function () {
  const $ = (s) => document.querySelector(s);

  // ===== elements =====
  const emailFallback = $("#emailFallback");
  const manualEmail = $("#manualEmail");
  const allowEmail = $("#allowEmail");

  const segNot = $("#segNot");
  const segIs = $("#segIs");
  const groupNot = $("#group-not");
  const groupIs = $("#group-is");

  // ===== read query =====
  const params = new URLSearchParams(location.search);
  const url = params.get("url") || "";
  const domain = params.get("domain") || (url ? safeHost(url) : "");
  const modelLabel = (params.get("model_label") || "-").toUpperCase();

  // ===== init =====
  $("#url").value = url;
  $("#domain").value = domain;
  applyStatusPill(modelLabel);

  // ===== email toggle =====
  allowEmail.addEventListener("change", () => {
    if (allowEmail.checked) {
      emailFallback.style.display = "block";
    } else {
      emailFallback.style.display = "none";
      manualEmail.value = "";
    }
  });

  // ===== segment switch =====
  let currentMode = "not_phishing";

  segNot.addEventListener("click", () => setMode("not_phishing"));
  segIs.addEventListener("click", () => setMode("is_phishing"));

  setMode(currentMode);

  // ===== back button =====
  $("#btnBack").addEventListener("click", () => {
    if (history.length > 1) history.back();
    else window.close();
  });

  // ===== submit =====
  $("#btnExport").addEventListener("click", () => {
    // optional email validation
    if (
      allowEmail.checked &&
      manualEmail.value &&
      !manualEmail.value.includes("@")
    ) {
      alert("กรุณากรอกอีเมลให้ถูกต้อง");
      return;
    }

    const payload = buildPayload();

    const email = allowEmail.checked ? (manualEmail.value || "") : "";

    chrome.runtime.sendMessage(
      {
        action: "feedback_add_and_send",
        ...payload,
        allow_email: allowEmail.checked,
        email: email,
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

  // ===== helpers =====

  function safeHost(u) {
    try {
      return new URL(u).hostname;
    } catch {
      return "";
    }
  }

  function applyStatusPill(label) {
    const pill = $("#statusPill");
    pill.textContent = label;
    pill.className = "pill";

    if (label === "SAFE") pill.classList.add("pill-good");
    else if (label === "SUSPECT") pill.classList.add("pill-warn");
    else if (label === "UNSAFE") pill.classList.add("pill-bad");
  }

  function setMode(mode) {
    currentMode = mode;

    if (mode === "not_phishing") {
      segNot.classList.add("active");
      segIs.classList.remove("active");
      groupNot.style.display = "";
      groupIs.style.display = "none";
    } else {
      segIs.classList.add("active");
      segNot.classList.remove("active");
      groupIs.style.display = "";
      groupNot.style.display = "none";
    }
  }

  function getFlagsFrom(container) {
    return Array.from(
      container.querySelectorAll('input[type="checkbox"]:checked')
    ).map((ch) => ch.value);
  }

  function buildPayload() {
    const ts = new Date().toISOString();

    if (currentMode === "not_phishing") {
      return {
        url,
        domain,
        model_label: modelLabel || "-",
        user_claim: "not_phishing",
        flags: getFlagsFrom(groupNot),
        note: $("#note").value || "",
        ts,
      };
    } else {
      return {
        url,
        domain,
        model_label: modelLabel || "-",
        user_claim: "is_phishing",
        flags: getFlagsFrom(groupIs),
        note: $("#note").value || "",
        ts,
      };
    }
  }
})();