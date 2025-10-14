// offscreen.js — รัน onnxruntime-web (WASM) ใน Offscreen Document
// ต้องมี <script src="vendor/ort.min.js"></script> ก่อนไฟล์นี้ (ดู offscreen.html)

const MODEL_PATH = "model/extension.onnx";
const FEATURE_ORDER_PATH = "model/extension_feature_order.json";
const UNSAFE_THRESHOLD = 0.515;

let session = null;
let featureOrder = null;
let initialized = false;

/* ------------------ Fetch helpers ------------------ */
async function fetchArrayBufferRelative(path) {
  const url = chrome.runtime.getURL(path);
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`Failed to fetch ${path} (${resp.status})`);
  return await resp.arrayBuffer();
}
async function fetchJsonRelative(path) {
  const url = chrome.runtime.getURL(path);
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`Failed to fetch JSON ${path} (${resp.status})`);
  return await resp.json();
}

/* ------------------ Feature extraction ------------------ */
function extractFeaturesFromUrl(url) {
  try {
    const u = new URL(url);
    const hostname = u.hostname;

    const length_url = url.length;
    const length_hostname = hostname.length;
    const ratio_digits_url = (url.match(/\d/g) || []).length / Math.max(1, url.length);
    const ratio_digits_host = (hostname.match(/\d/g) || []).length / Math.max(1, hostname.length);
    const nb_subdomains = Math.max(0, hostname.split(".").length - 2);
    const prefix_suffix = /-|_/.test(hostname) ? 1 : 0;
    const uses_https = u.protocol === "https:" ? 1 : 0;
    const is_http = u.protocol === "http:" ? 1 : 0;
    const num_query_params = u.searchParams ? [...u.searchParams].length : 0;
    const has_at_symbol = url.includes("@") ? 1 : 0;

    // Shannon entropy
    let url_entropy = 0;
    const map = {};
    for (const ch of url) map[ch] = (map[ch] || 0) + 1;
    for (const k in map) {
      const p = map[k] / url.length;
      url_entropy -= p * Math.log2(p);
    }

    const url_length_ratio = length_url / (length_hostname + 1);
    const digit_ratio_diff = Math.abs(ratio_digits_url - ratio_digits_host);

    return {
      length_url,
      length_hostname,
      ratio_digits_url,
      ratio_digits_host,
      nb_subdomains,
      tld_in_path: 0,
      tld_in_subdomain: 0,
      shortening_service: 0,
      prefix_suffix,
      url_entropy,
      uses_https,
      is_http,
      num_query_params,
      has_at_symbol,
      path_extension: 0,
      tld_risk: 0,
      typosquat_candidate: 0,
      typosquat_score_max: 0,
      typosquat_score_mean: 0,
      typosquat_distance: 0,
      url_length_ratio,
      digit_ratio_diff
    };
  } catch {
    return null;
  }
}

function buildInputTensor(featuresObj) {
  if (!featureOrder) throw new Error("featureOrder not loaded");
  const arr = new Float32Array(featureOrder.length);
  for (let i = 0; i < featureOrder.length; i++) arr[i] = Number(featuresObj[featureOrder[i]] ?? 0);
  return new ort.Tensor("float32", arr, [1, featureOrder.length]);
}

/* ------------------ Output readers ------------------ */
function readNumberFromTensor(t) {
  try {
    const arr = t?.data;
    if (!arr || arr.length === 0) return null;

    if (arr.length === 2) return typeof arr[1] === "number" ? arr[1] : null; // [p0,p1]
    if (arr.length === 1) {
      const v = arr[0];
      if (typeof v !== "number") return null;
      if (v < 0 || v > 1) return 1 / (1 + Math.exp(-v)); // logits → prob
      return v;
    }
    const last = arr[arr.length - 1];
    return typeof last === "number" ? last : null;
  } catch { return null; }
}

function readNumberFromMap(m) {
  try {
    const kt = m?.keys, vt = m?.values;
    if (!kt?.data || !vt?.data) return null;
    const keys = kt.data, vals = vt.data;

    let idx = -1;
    for (let i = 0; i < keys.length; i++) {
      const k = String(keys[i]).toLowerCase();
      if (k === "1" || k.includes("unsafe") || k.includes("phishing")) { idx = i; break; }
    }
    if (idx >= 0 && typeof vals[idx] === "number") return vals[idx];

    let max = -Infinity;
    for (let i = 0; i < vals.length; i++) if (vals[i] > max) max = vals[i];
    return isFinite(max) ? max : null;
  } catch { return null; }
}

function readNumberFromValue(v) {
  if (v && typeof v === "object" && "data" in v) return readNumberFromTensor(v);
  if (v && typeof v === "object" && v.keys && v.values) return readNumberFromMap(v);
  if (Array.isArray(v)) {
    for (const it of v) {
      const n = readNumberFromValue(it);
      if (n != null) return n;
    }
  }
  return null;
}

function pickUnsafeProbabilityFromResults(results, outputNames) {
  const preferred = ["probabilities","probability","proba","scores","logits","output_probability","output_prob"];
  for (const name of preferred) {
    if (Object.prototype.hasOwnProperty.call(results, name)) {
      const num = readNumberFromValue(results[name]);
      if (num != null) return num;
    }
  }
  for (const name of outputNames || []) {
    if (!Object.prototype.hasOwnProperty.call(results, name)) continue;
    const num = readNumberFromValue(results[name]);
    if (num != null) return num;
  }
  for (const [k, v] of Object.entries(results)) {
    const num = readNumberFromValue(v);
    if (num != null) return num;
  }
  return 0;
}

/* ------------------ Load & init ------------------ */
async function createSessionWasmWithFallback(modelBin) {
  ort.env.wasm.wasmPaths = chrome.runtime.getURL("vendor/");
  try {
    ort.env.wasm.numThreads = 1;
    ort.env.wasm.simd = true;
    const s1 = await ort.InferenceSession.create(modelBin, {
      executionProviders: ["wasm"],
      graphOptimizationLevel: "all"
    });
    console.log("✅ ONNX session ready (WASM single-thread)");
    return s1;
  } catch (e1) { console.warn("Single-thread failed → try threaded", e1); }
  try {
    ort.env.wasm.numThreads = 2;
    ort.env.wasm.simd = true;
    const s2 = await ort.InferenceSession.create(modelBin, {
      executionProviders: ["wasm"],
      graphOptimizationLevel: "all"
    });
    console.log("✅ ONNX session ready (WASM threaded)");
    return s2;
  } catch (e2) {
    console.warn("Threaded WASM failed", e2);
    throw e2;
  }
}

async function loadOrtAndModelSafe() {
  if (initialized) return { status: "already" };
  try {
    if (!window.ort) throw new Error("ort not found. Ensure vendor/ort.min.js is loaded first");

    const [modelBin, order] = await Promise.all([
      fetchArrayBufferRelative(MODEL_PATH),
      fetchJsonRelative(FEATURE_ORDER_PATH)
    ]);

    featureOrder = order;
    session = await createSessionWasmWithFallback(modelBin);

    initialized = true;
    console.log("✅ Model loaded. Feature count:", featureOrder?.length ?? 0);
    chrome.runtime.sendMessage({ action: "offscreenReady" });
    return { status: "ok" };
  } catch (err) {
    console.error("❌ Failed to load model:", err);
    chrome.runtime.sendMessage({ action: "offscreenReady" });
    return { status: "error", error: String(err) };
  }
}

/* ------------------ Inference ------------------ */
async function runInference(url) {
  if (!session || !featureOrder) return { prediction: 0, unsafe_probability: 0 };
  const features = extractFeaturesFromUrl(url);
  if (!features) return { prediction: 0, unsafe_probability: 0 };

  try {
    const inputTensor = buildInputTensor(features);
    const feeds = { [session.inputNames[0]]: inputTensor };
    const results = await session.run(feeds);

    let unsafe_prob = null;
    const firstName = session.outputNames?.[0];
    const firstOut = firstName ? results[firstName] : null;
    if (firstOut && firstOut.data) unsafe_prob = readNumberFromTensor(firstOut);
    if (unsafe_prob == null) unsafe_prob = pickUnsafeProbabilityFromResults(results, session.outputNames);

    if (!isFinite(unsafe_prob)) unsafe_prob = 0;
    unsafe_prob = Math.max(0, Math.min(1, unsafe_prob));

    const prediction = unsafe_prob >= UNSAFE_THRESHOLD ? 1 : 0;
    return { prediction, unsafe_probability: unsafe_prob };
  } catch (err) {
    console.error("Inference error:", err);
    return { prediction: 0, unsafe_probability: 0 };
  }
}

/* ------------------ Message handling ------------------ */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      if (message?.action === "ping") return sendResponse({ ok: true });
      if (message?.action === "check_url" && message.url) {
        if (!initialized) await loadOrtAndModelSafe();
        const res = await runInference(message.url);
        return sendResponse(res);
      }
      if (message?.action === "preload_model") {
        const res = await loadOrtAndModelSafe();
        return sendResponse(res);
      }
    } catch (e) {
      return sendResponse({ status: "error", error: String(e) });
    }
  })();
  return true; // async
});

/* ------------------ Auto init ------------------ */
(async () => { await loadOrtAndModelSafe(); })();
