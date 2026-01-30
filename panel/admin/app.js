(function () {
  const CFG = window.YINN_PANEL || {
    API_BASE: "",
    VERIFY_PATH: "/api/auth",
    CREATE_PATH: "/api/create",
    HEALTH_PATH: "/health",
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
  const btnToggleRaw = $("btnToggleRaw");

  const LS_KEY = "yinn_panel_token";

  let SHOW_RAW = false;
  let LAST_RAW = "";     // simpan raw terakhir
  let LAST_SMART = "";   // simpan smart terakhir

  function setMsg(text, kind = "ok") {
    loginMsg.textContent = text;
    loginMsg.className = `msg show ${kind}`;
  }
  function hideMsg() {
    loginMsg.className = "msg";
    loginMsg.textContent = "";
  }

  function getToken() { return localStorage.getItem(LS_KEY) || ""; }
  function setToken(t) { localStorage.setItem(LS_KEY, t); }
  function clearToken() { localStorage.removeItem(LS_KEY); }

  function setApiState(state, label) {
    apiLed.className = "led " + (state === "ok" ? "led-ok" : state === "err" ? "led-err" : "led-warn");
    apiText.textContent = label;
  }

  function apiUrl(path) {
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

  function nowStr() {
    const d = new Date();
    const pad = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  // ===== Output Cleaning =====
  function stripAnsi(s) {
    return (s || "").replace(/\x1b\[[0-9;]*m/g, "").replace(/\r/g, "");
  }

  function normalizeRaw(raw) {
    const t = stripAnsi(raw || "");
    const lines = t.split("\n").map(l => (l || "").replace(/^\s*-e\s+/g, "").replace(/[ \t]+$/g, ""));
    // buang spam 'unknown'
    const filtered = lines.filter(l => {
      if (!l) return false;
      if (/^'unknown'\s*:\s*I need something more specific\./i.test(l)) return false;
      if (/I need something more specific\./i.test(l)) return false;
      if (/^\s*loading\.\.\.\s*$/i.test(l)) return false;
      return true;
    });
    return filtered.join("\n").trim();
  }

  // ambil blok penting dari output autoscript (SSH/VMESS/VLESS/TROJAN beda-beda, kita pakai heuristic)
  function smartExtract(raw) {
    const t = normalizeRaw(raw);
    if (!t) return "";

    const lines = t.split("\n");

    const keep = [];
    const importantKeys = [
      "Username", "Password", "Host", "IP", "Domain", "Expired", "Limit Ip",
      "Port", "OpenSSH", "Dropbear", "SSH WS", "SSH SSL", "WS", "WSS",
      "Vmess", "Vless", "Trojan", "UUID", "Path", "TLS", "SNI",
      "Link", "Config", "Public Key", "Pub Key", "Location", "Isp", "ASN"
    ];

    const keyRe = new RegExp(`^\\s*(${importantKeys.map(k=>k.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")).join("|")})\\b`, "i");

    // keep judul box sederhana
    const boxRe = /^(=+|─+|━+|╭|╰|┌|└|│|╞|╡|╭─|╰─|•)/;

    for (const line of lines) {
      const s = line.trim();
      if (!s) continue;

      // kalau ada indikasi error serius
      if (/PERMISSION DENIED|Banned|404 NOT FOUND|Unauthorized/i.test(s)) {
        keep.push(`[ERROR] ${s}`);
        continue;
      }

      // simpan status sukses
      if (/Status\s+Create/i.test(s) || /Create\s+(SSH|VMESS|VLESS|TROJAN)/i.test(s)) {
        keep.push(s);
        continue;
      }

      // simpan key-value penting
      if (keyRe.test(s)) {
        keep.push(s);
        continue;
      }

      // simpan link yang jelas
      if (/https?:\/\/\S+/i.test(s)) {
        keep.push(s);
        continue;
      }

      // simpan garis tapi dibatasi biar gak spam
      if (boxRe.test(s) && s.length < 60) {
        keep.push(s);
        continue;
      }
    }

    // fallback kalau heuristic terlalu ketat
    if (keep.length < 6) return t;

    // remove duplikat berurutan
    const out = [];
    for (const k of keep) {
      if (out[out.length - 1] !== k) out.push(k);
    }
    return out.join("\n").trim();
  }

  function renderTerminal(text, mode = "append", kind = "normal") {
    const lines = (text || "").split("\n");
    if (mode === "replace") terminal.innerHTML = "";

    for (const line of lines) {
      const div = document.createElement("div");
      div.className = "term-line";
      if (kind === "dim") div.classList.add("dim");
      if (/^\[ERROR\]/i.test(line)) div.classList.add("hl-err");
      if (/Status\s+Create/i.test(line)) div.classList.add("hl-ok");
      terminal.appendChild(div).textContent = line;
    }
    terminal.scrollTop = terminal.scrollHeight;
  }

  function showOutput(raw) {
    LAST_RAW = normalizeRaw(raw);
    LAST_SMART = smartExtract(raw);

    terminal.innerHTML = "";

    if (SHOW_RAW) {
      renderTerminal(LAST_RAW || "(empty)", "append");
    } else {
      renderTerminal(LAST_SMART || "(empty)", "append");
      renderTerminal(`\n# Tip: klik "Raw" buat lihat full output`, "append", "dim");
    }
  }

  function getTerminalPlainText() {
    return Array.from(terminal.querySelectorAll(".term-line"))
      .map(el => el.textContent || "")
      .join("\n")
      .trim();
  }

  // ===== Health + Verify =====
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
    const headers = { "Authorization": `Bearer ${t}` };

    let r = await fetchJSON(url, { method: "POST", headers }, 12000);
    if (r.res && r.res.status === 405) r = await fetchJSON(url, { method: "GET", headers }, 12000);

    const { res, data } = r;
    if (!res) return { ok: false, msg: "No response" };
    if (res.status === 401) return { ok: false, msg: "Token salah / revoked" };

    const okFlag = !!(data && (data.ok === true || data.success === true || data.valid === true || data.authorized === true));
    if (res.ok && (okFlag || res.status === 200)) return { ok: true, msg: "Token valid" };

    const detail = (data && (data.detail || data.message || data.error || data._raw)) || `Verify gagal (${res.status})`;
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
        showOutput(`# Welcome, token verified\n# ${nowStr()}\n`);
        outMeta.textContent = `Ready • ${nowStr()}`;
        return;
      }
    }

    showLoginUI();
  }

  // ===== Events =====
  btnToggleRaw?.addEventListener("click", () => {
    SHOW_RAW = !SHOW_RAW;
    btnToggleRaw.textContent = SHOW_RAW ? "Smart" : "Raw";
    // rerender last output
    if (LAST_RAW || LAST_SMART) showOutput(LAST_RAW || LAST_SMART || "");
  });

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
    showOutput(`# Login success\n# ${nowStr()}\n`);
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
    showOutput(`# Logged out\n# ${nowStr()}\n`);
    outMeta.textContent = `—`;
  });

  btnClearForm.addEventListener("click", () => {
    username.value = "";
    password.value = "";
    iplimit.value = "2";
    days.value = "1";
  });

  btnCopyOut.addEventListener("click", async () => {
    const text = getTerminalPlainText();
    if (!text) {
      outMeta.textContent = `Nothing to copy • ${nowStr()}`;
      return;
    }

    try {
      await navigator.clipboard.writeText(text);
      outMeta.textContent = `Copied ✅ • ${nowStr()}`;
      return;
    } catch {}

    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      ta.style.top = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      ta.setSelectionRange(0, ta.value.length);
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      outMeta.textContent = ok ? `Copied ✅ • ${nowStr()}` : `Copy failed • ${nowStr()}`;
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

    // ✅ prompt singkat, gak spam
    showOutput(`$ create ${payload.proto} user=${payload.username} iplimit=${payload.iplimit} days=${payload.days}\n`);

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
      showOutput(`[ERROR] Network error: ${String(e)}\n`);
      outMeta.textContent = `Failed • ${nowStr()}`;
      return;
    }

    if (!res) {
      showOutput(`[ERROR] No response\n`);
      outMeta.textContent = `Failed • ${nowStr()}`;
      return;
    }

    if (res.status === 401) {
      showOutput(`[401] Unauthorized — token invalid/revoked\n`);
      clearToken();
      showLoginUI();
      setMsg("Token invalid/revoked. Login ulang.", "err");
      outMeta.textContent = `Unauthorized • ${nowStr()}`;
      return;
    }

    if (!res.ok) {
      const msg = (data && (data.detail || data.message || data.error || data._raw)) || `HTTP ${res.status}`;
      showOutput(`[ERROR] ${msg}\n`);
      outMeta.textContent = `Failed • ${nowStr()}`;
      return;
    }

    const out = (data && data.output) ? data.output : JSON.stringify(data);
    showOutput(out + "\n");
    outMeta.textContent = `Done • ${nowStr()}`;
  });

  boot();
  setInterval(checkHealth, 8000);
})();