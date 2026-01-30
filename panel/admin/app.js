(function () {
  // =============== CONFIG (match app.py) ===============
  const CFG = window.YINN_PANEL || {
    API_BASE: "",
    VERIFY_PATH: "/api/auth",
    CREATE_PATH: "/api/create",
    HEALTH_PATH: "/health"
  };

  const $ = (id) => document.getElementById(id);

  // =============== ELEMENTS ===============
  const loginCard = $("loginCard");
  const appCard = $("appCard");

  const tokenInput = $("tokenInput");
  const loginMsg = $("loginMsg");

  const apiLed = $("apiLed");
  const apiText = $("apiText");
  const btnLogout = $("btnLogout");

  const proto = $("proto");
  const username = $("username");

  // SSH only
  const passRow = $("passRow");
  const password = $("password");

  // ALL proto
  const iplimit = $("iplimit");
  const days = $("days");

  // XRAY only
  const quotaRow = $("quotaRow");
  const quotaGb = $("quota_gb");

  const terminal = $("terminal");
  const outMeta = $("outMeta");

  const btnLogin = $("btnLogin");
  const btnClearToken = $("btnClearToken");
  const btnCreate = $("btnCreate");
  const btnClearForm = $("btnClearForm");
  const btnCopyOut = $("btnCopyOut");
  const btnToggleRaw = $("btnToggleRaw");

  const LS_KEY = "yinn_panel_token";

  // =============== UI HELPERS ===============
  function setMsg(text, kind = "ok") {
    loginMsg.textContent = text;
    loginMsg.className = `msg show ${kind}`;
  }
  function hideMsg() {
    loginMsg.className = "msg";
    loginMsg.textContent = "";
  }

  function setApiState(state, label) {
    apiLed.className =
      "led " +
      (state === "ok" ? "led-ok" : state === "err" ? "led-err" : "led-warn");
    apiText.textContent = label;
  }

  function getToken() {
    return localStorage.getItem(LS_KEY) || "";
  }
  function setToken(t) {
    localStorage.setItem(LS_KEY, t);
  }
  function clearToken() {
    localStorage.removeItem(LS_KEY);
  }

  function apiUrl(path) {
    const base = (CFG.API_BASE || "").replace(/\/+$/, "");
    const p = (path || "").startsWith("/") ? path : `/${path}`;
    return `${base}${p}`;
  }

  function nowStr() {
    const d = new Date();
    const pad = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(
      d.getHours()
    )}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  function stripAnsi(s) {
    return (s || "").replace(/\x1b\[[0-9;]*m/g, "").replace(/\r/g, "");
  }

  let RAW_MODE = false;
  function termWrite(text, mode = "append", cls = "") {
    const t = RAW_MODE ? (text || "") : stripAnsi(text || "");
    if (mode === "replace") terminal.innerHTML = "";
    const lines = t.split("\n");
    for (const line of lines) {
      const div = document.createElement("div");
      div.className = "term-line" + (cls ? ` ${cls}` : "");
      div.textContent = line;
      terminal.appendChild(div);
    }
    terminal.scrollTop = terminal.scrollHeight;
  }

  // =============== FETCH HELPERS ===============
  async function fetchJSON(url, opts = {}, timeoutMs = 12000) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetch(url, {
        cache: "no-store",
        credentials: "same-origin",
        signal: controller.signal,
        ...opts,
        headers: {
          Accept: "application/json",
          "Cache-Control": "no-cache",
          ...(opts.headers || {})
        }
      });

      const text = await res.text();
      let data = null;
      try {
        data = text ? JSON.parse(text) : null;
      } catch {
        data = { _raw: text || "" };
      }
      return { res, data };
    } finally {
      clearTimeout(id);
    }
  }

  // =============== API CHECKS ===============
  async function checkHealth() {
    try {
      const { res } = await fetchJSON(apiUrl(CFG.HEALTH_PATH), { method: "GET" }, 8000);
      if (res && res.ok) setApiState("ok", "API: OK");
      else setApiState("warn", "API: CHECK...");
    } catch {
      setApiState("err", "API: DOWN");
    }
  }

  async function verifyToken(token) {
    const t = (token || "").trim();
    if (!t) return { ok: false, msg: "Token kosong." };

    const url = apiUrl(CFG.VERIFY_PATH);
    const headers = {
      Authorization: `Bearer ${t}`,
      "Cache-Control": "no-store"
    };

    let r = await fetchJSON(url, { method: "POST", headers }, 12000);
    if (r.res && r.res.status === 405) {
      r = await fetchJSON(url, { method: "GET", headers }, 12000);
    }

    const { res, data } = r;
    if (!res) return { ok: false, msg: "No response" };
    if (res.status === 401) return { ok: false, msg: "Token salah / revoked" };

    const okFlag =
      data &&
      (data.ok === true ||
        data.success === true ||
        data.valid === true ||
        data.authorized === true);

    if (res.ok && (okFlag || res.status === 200)) return { ok: true, msg: "Token valid" };

    const detail =
      (data && (data.detail || data.message || data.error || data._raw)) ||
      `Verify gagal (${res.status})`;

    return { ok: false, msg: detail };
  }

  // =============== FORM LOGIC: SSH vs XRAY ===============
  function isXray(p) {
    return ["vmess", "vless", "trojan"].includes((p || "").toLowerCase());
  }

  function show(el, on) {
    if (!el) return;
    el.classList.toggle("hidden", !on);
  }

  function syncFormByProto() {
    const p = (proto.value || "ssh").toLowerCase();
    const x = isXray(p);

    // SSH: password visible
    show(passRow, !x);
    if (password) {
      password.disabled = x;
      if (x) password.value = "";
    }

    // XRAY: quota visible
    show(quotaRow, x);
    if (quotaGb) {
      quotaGb.disabled = !x;
      if (!x) quotaGb.value = "0";
    }
  }

  function numVal(el, fallback) {
    const n = Number((el && el.value) || "");
    return Number.isFinite(n) ? n : fallback;
  }

  function buildPayload() {
    const p = (proto.value || "ssh").toLowerCase();
    const u = (username.value || "").trim();
    const d = numVal(days, 1);
    const ip = numVal(iplimit, 0);

    if (!u) throw new Error("Username wajib diisi.");
    if (d < 1) throw new Error("Expired minimal 1 hari.");
    if (ip < 0) throw new Error("Limit IP tidak valid.");

    if (!isXray(p)) {
      const pw = (password && password.value ? password.value : "").trim();
      if (pw.length < 1) throw new Error("Password minimal 1 karakter.");
      return { proto: p, username: u, password: pw, iplimit: ip, days: d };
    }

    const q = numVal(quotaGb, 0);
    if (q < 0) throw new Error("Quota tidak valid.");

    return { proto: p, username: u, days: d, quota_gb: q, iplimit: ip };
  }

  // =============== COPY OUTPUT ===============
  async function copyToClipboard(text) {
    const t = (text || "").trim();
    if (!t) return false;

    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(t);
      return true;
    }

    const ta = document.createElement("textarea");
    ta.value = t;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  }

  // =============== UI SWITCH ===============
  function showAppUI() {
    loginCard.classList.add("hidden");
    appCard.classList.remove("hidden");
  }
  function showLoginUI() {
    appCard.classList.add("hidden");
    loginCard.classList.remove("hidden");
  }

  // =============== BOOT ===============
  async function boot() {
    await checkHealth();
    syncFormByProto();

    const t = getToken();
    if (t) {
      const v = await verifyToken(t);
      if (v.ok) {
        showAppUI();
        termWrite(`# Login success`, "replace", "hl-ok");
        termWrite(`# ${nowStr()}`, "append");
        outMeta.textContent = `Logged in • ${nowStr()}`;
        return;
      }
    }
    showLoginUI();
  }

  // =============== EVENTS ===============
  proto.addEventListener("change", syncFormByProto);

  btnLogin.addEventListener("click", async () => {
    hideMsg();
    const t = (tokenInput.value || "").trim();
    if (!t) return setMsg("Token wajib diisi.", "err");

    setMsg("Validating token...", "ok");
    const v = await verifyToken(t);
    if (!v.ok) return setMsg(v.msg, "err");

    setToken(t);
    setMsg("Login sukses. Token valid ✅", "ok");
    showAppUI();
    termWrite(`# Login success`, "replace", "hl-ok");
    termWrite(`# ${nowStr()}`, "append");
    outMeta.textContent = `Logged in • ${nowStr()}`;
  });

  btnClearToken.addEventListener("click", () => {
    tokenInput.value = "";
    hideMsg();
  });

  btnLogout.addEventListener("click", () => {
    clearToken();
    tokenInput.value = "";
    showLoginUI();
    setMsg("Logout sukses. Token dihapus.", "ok");
    termWrite(`# Logged out`, "replace");
    termWrite(`# ${nowStr()}`, "append");
    outMeta.textContent = `—`;
  });

  btnClearForm.addEventListener("click", () => {
    username.value = "";
    if (password) password.value = "";
    iplimit.value = "2";
    days.value = "1";
    if (quotaGb) quotaGb.value = "0";
    syncFormByProto();
  });

  btnCopyOut.addEventListener("click", async () => {
    const text = terminal.innerText || "";
    try {
      const ok = await copyToClipboard(text);
      outMeta.textContent = (ok ? `Copied` : `Copy failed`) + ` • ${nowStr()}`;
    } catch {
      outMeta.textContent = `Copy failed • ${nowStr()}`;
    }
  });

  if (btnToggleRaw) {
    btnToggleRaw.addEventListener("click", () => {
      RAW_MODE = !RAW_MODE;
      btnToggleRaw.textContent = RAW_MODE ? "Clean" : "Raw";
      outMeta.textContent = `Mode: ${RAW_MODE ? "RAW" : "CLEAN"} • ${nowStr()}`;
    });
  }

  btnCreate.addEventListener("click", async () => {
    const t = getToken();
    if (!t) {
      showLoginUI();
      setMsg("Token hilang. Login ulang.", "err");
      return;
    }

    let payload;
    try {
      payload = buildPayload();
    } catch (e) {
      termWrite(`\n[ERROR] ${String(e.message || e)}\n`, "append", "hl-err");
      outMeta.textContent = `Failed • ${nowStr()}`;
      return;
    }

    termWrite(`\n$ curl -X POST ${location.origin}${apiUrl(CFG.CREATE_PATH)} \\`, "append");
    termWrite(`  -H "Authorization: Bearer ********" \\`, "append");
    termWrite(`  -H "Content-Type: application/json" \\`, "append");
    termWrite(`  -d '${JSON.stringify(payload)}'`, "append");

    outMeta.textContent = `Running... • ${nowStr()}`;

    let res, data;
    try {
      ({ res, data } = await fetchJSON(
        apiUrl(CFG.CREATE_PATH),
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${t}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify(payload)
        },
        180000
      ));
    } catch (e) {
      termWrite(`\n[ERROR] Network error: ${String(e)}\n`, "append", "hl-err");
      outMeta.textContent = `Failed • ${nowStr()}`;
      return;
    }

    if (!res) {
      termWrite(`\n[ERROR] No response\n`, "append", "hl-err");
      outMeta.textContent = `Failed • ${nowStr()}`;
      return;
    }

    if (res.status === 401) {
      termWrite(`\n[401] Unauthorized — token invalid/revoked\n`, "append", "hl-err");
      clearToken();
      showLoginUI();
      setMsg("Token invalid/revoked. Login ulang.", "err");
      outMeta.textContent = `Unauthorized • ${nowStr()}`;
      return;
    }

    if (!res.ok) {
      const msg =
        (data && (data.detail || data.message || data.error || data._raw)) ||
        `HTTP ${res.status}`;
      termWrite(`\n[ERROR] ${msg}\n`, "append", "hl-err");
      outMeta.textContent = `Failed • ${nowStr()}`;
      return;
    }

    const out = data && data.output ? data.output : JSON.stringify(data);
    termWrite(`\n${out}\n`, "append");
    outMeta.textContent = `Done • ${nowStr()}`;
  });

  // =============== START ===============
  boot();
  setInterval(checkHealth, 8000);
})();