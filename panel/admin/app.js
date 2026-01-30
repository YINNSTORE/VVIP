(function () {
  // FIX: default config harus match API lu
  const CFG = window.YINN_PANEL || {
    API_BASE: "",                 // kosong = same-origin
    VERIFY_PATH: "/api/auth",     // ✅ FIX (bukan /api/auth/verify)
    CREATE_PATH: "/api/create",
    HEALTH_PATH: "/health"
  };

  const $ = (id) => document.getElementById(id);

  const loginCard = $("loginCard");
  const appCard = $("appCard");

  const tokenInput = $("tokenInput");
  const loginMsg = $("loginMsg");

  const apiLed = $("apiLed");
  const apiText = $("apiText");
  const btnLogout = $("btnLogout");

  const proto = $("proto");
  const username = $("username");
  const password = $("password");
  const iplimit = $("iplimit");
  const days = $("days");

  const terminal = $("terminal");
  const outMeta = $("outMeta");

  const btnLogin = $("btnLogin");
  const btnClearToken = $("btnClearToken");
  const btnCreate = $("btnCreate");
  const btnClearForm = $("btnClearForm");
  const btnCopyOut = $("btnCopyOut");

  const LS_KEY = "yinn_panel_token";

  function setMsg(text, kind = "ok") {
    loginMsg.textContent = text;
    loginMsg.className = `msg show ${kind}`;
  }
  function hideMsg() {
    loginMsg.className = "msg";
    loginMsg.textContent = "";
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

  function setApiState(state, label) {
    apiLed.className = "led " + (state === "ok" ? "led-ok" : state === "err" ? "led-err" : "led-warn");
    apiText.textContent = label;
  }

  function apiUrl(path) {
    // normalize (hindari double slash)
    const base = (CFG.API_BASE || "").replace(/\/+$/, "");
    const p = (path || "").startsWith("/") ? path : `/${path}`;
    return `${base}${p}`;
  }

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
          "Accept": "application/json",
          "Cache-Control": "no-cache",
          ...(opts.headers || {}),
        },
      });

      let data = null;
      const text = await res.text();
      try { data = text ? JSON.parse(text) : null; } catch { data = { _raw: text || "" }; }
      return { res, data };
    } finally {
      clearTimeout(id);
    }
  }

  function stripAnsi(s) {
    return (s || "").replace(/\x1b\[[0-9;]*m/g, "").replace(/\r/g, "");
  }

  function termWrite(text, mode = "append") {
    const t = stripAnsi(text);
    if (mode === "replace") terminal.innerHTML = "";
    const lines = t.split("\n");
    for (const line of lines) {
      const div = document.createElement("div");
      div.className = "term-line";
      div.textContent = line;
      terminal.appendChild(div);
    }
    terminal.scrollTop = terminal.scrollHeight;
  }

  function nowStr() {
    const d = new Date();
    const pad = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  async function checkHealth() {
    try {
      const { res } = await fetchJSON(apiUrl(CFG.HEALTH_PATH), { method: "GET" }, 8000);
      if (res && res.ok) setApiState("ok", "API: OK");
      else setApiState("warn", "API: CHECK...");
    } catch {
      setApiState("err", "API: DOWN");
    }
  }

  // ✅ FIX: verify robust (POST first, fallback GET, tolerant ok)
  async function verifyToken(token) {
    const t = (token || "").trim();
    if (!t) return { ok: false, msg: "Token kosong." };

    const url = apiUrl(CFG.VERIFY_PATH);
    const headers = {
      "Authorization": `Bearer ${t}`,
      "Cache-Control": "no-store",
    };

    // try POST
    let r = await fetchJSON(url, { method: "POST", headers }, 12000);

    // fallback GET if 405 Method Not Allowed
    if (r.res && r.res.status === 405) {
      r = await fetchJSON(url, { method: "GET", headers }, 12000);
    }

    const { res, data } = r;

    if (!res) return { ok: false, msg: "No response" };

    if (res.status === 401) return { ok: false, msg: "Token salah / revoked" };

    // tolerate various ok flags OR status 200
    const okFlag =
      (data && (data.ok === true || data.success === true || data.valid === true || data.authorized === true));

    if (res.ok && (okFlag || res.status === 200)) return { ok: true, msg: "Token valid" };

    const detail =
      (data && (data.detail || data.message || data.error || data._raw)) || `Verify gagal (${res.status})`;

    return { ok: false, msg: detail };
  }

  function showAppUI() {
    loginCard.classList.add("hidden");
    appCard.classList.remove("hidden");
  }
  function showLoginUI() {
    appCard.classList.add("hidden");
    loginCard.classList.remove("hidden");
  }

  async function boot() {
    await checkHealth();
    const t = getToken();
    if (t) {
      const v = await verifyToken(t);
      if (v.ok) {
        showAppUI();
        termWrite(`# Welcome, token verified\n# ${nowStr()}\n`, "replace");
        outMeta.textContent = `Ready • ${nowStr()}`;
        return;
      }
    }
    showLoginUI();
  }

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
    termWrite(`# Login success\n# ${nowStr()}\n`, "replace");
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
    termWrite(`# Logged out\n# ${nowStr()}\n`, "replace");
    outMeta.textContent = `—`;
  });

  btnClearForm.addEventListener("click", () => {
    username.value = "";
    password.value = "";
    iplimit.value = "2";
    days.value = "1";
  });

  btnCopyOut.addEventListener("click", async () => {
    const text = terminal.innerText || "";
    try {
      await navigator.clipboard.writeText(text);
      outMeta.textContent = `Copied • ${nowStr()}`;
    } catch {
      outMeta.textContent = `Copy failed • ${nowStr()}`;
    }
  });

  btnCreate.addEventListener("click", async () => {
    const t = getToken();
    if (!t) {
      showLoginUI();
      setMsg("Token hilang. Login ulang.", "err");
      return;
    }

    const payload = {
      proto: (proto.value || "ssh"),
      username: (username.value || "").trim(),
      password: (password.value || "").trim(),
      iplimit: Number(iplimit.value || 0),
      days: Number(days.value || 1),
    };

    termWrite(
      `\n$ curl -X POST ${location.origin}${apiUrl(CFG.CREATE_PATH)} \\\n` +
      `  -H "Authorization: Bearer ********" \\\n` +
      `  -H "Content-Type: application/json" \\\n` +
      `  -d '${JSON.stringify(payload)}'\n`,
      "append"
    );

    outMeta.textContent = `Running... • ${nowStr()}`;

    let res, data;
    try {
      ({ res, data } = await fetchJSON(apiUrl(CFG.CREATE_PATH), {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${t}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      }, 180000));
    } catch (e) {
      termWrite(`\n[ERROR] Network error: ${String(e)}\n`, "append");
      outMeta.textContent = `Failed • ${nowStr()}`;
      return;
    }

    if (!res) {
      termWrite(`\n[ERROR] No response\n`, "append");
      outMeta.textContent = `Failed • ${nowStr()}`;
      return;
    }

    if (res.status === 401) {
      termWrite(`\n[401] Unauthorized — token invalid/revoked\n`, "append");
      clearToken();
      showLoginUI();
      setMsg("Token invalid/revoked. Login ulang.", "err");
      outMeta.textContent = `Unauthorized • ${nowStr()}`;
      return;
    }

    if (!res.ok) {
      const msg = (data && (data.detail || data.message || data.error)) || `HTTP ${res.status}`;
      termWrite(`\n[ERROR] ${msg}\n`, "append");
      outMeta.textContent = `Failed • ${nowStr()}`;
      return;
    }

    const out = (data && data.output) ? data.output : JSON.stringify(data);
    termWrite(`\n${out}\n`, "append");
    outMeta.textContent = `Done • ${nowStr()}`;
  });

  boot();
  setInterval(checkHealth, 8000);
})();