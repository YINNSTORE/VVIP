// endpoint.js (FULL FIX - robust, tolerate 200/JSON mismatch, fallback POST->GET)
// API_BASE kosong = same-origin (panel.domain) => aman
export const API_BASE = "";

// ===== utils =====
function trimToken(token) {
  return (token || "").toString().trim();
}

async function safeRead(res) {
  const text = await res.text();
  if (!text) return { _raw: "" };
  try {
    return JSON.parse(text);
  } catch {
    return { _raw: text };
  }
}

function pickDetail(data) {
  if (!data) return "";
  return (
    data.detail ||
    data.error ||
    data.message ||
    data.msg ||
    data._raw ||
    ""
  );
}

async function requestJson(url, options = {}, timeoutMs = 12000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      cache: "no-store",
      credentials: "same-origin",
      signal: controller.signal,
      ...options,
      headers: {
        "Accept": "application/json",
        "Cache-Control": "no-cache",
        ...(options.headers || {}),
      },
    });

    const data = await safeRead(res);
    return { res, data };
  } finally {
    clearTimeout(id);
  }
}

// ===== API =====
export async function verifyToken(token) {
  const t = trimToken(token);
  if (!t) return { ok: false, status: 0, detail: "Empty token", data: null };

  const url = `${API_BASE}/api/auth`;
  const headers = { Authorization: `Bearer ${t}` };

  // 1) coba POST dulu (yang paling bener)
  let out;
  try {
    out = await requestJson(
      url,
      { method: "POST", headers },
      12000
    );
  } catch (e) {
    return {
      ok: false,
      status: 0,
      detail: `Network error: ${e?.message || e}`,
      data: null,
    };
  }

  // fallback: kalau server lu ternyata cuma allow GET (atau ada proxy aneh)
  if (out.res && out.res.status === 405) {
    try {
      out = await requestJson(
        url,
        { method: "GET", headers },
        12000
      );
    } catch (e) {
      return {
        ok: false,
        status: 0,
        detail: `Network error: ${e?.message || e}`,
        data: null,
      };
    }
  }

  const { res, data } = out;

  // ok flag tolerant
  const okFlag =
    data?.ok === true ||
    data?.success === true ||
    data?.valid === true ||
    data?.authorized === true;

  // ✅ aturan sukses:
  // - status 2xx
  // - kalau body json ada okFlag true -> sukses
  // - kalau ga ada okFlag tapi status 200 dan body kosong/mentah -> anggap sukses
  const raw = (data && typeof data._raw === "string") ? data._raw.trim() : "";
  const ok =
    res.ok &&
    (okFlag || res.status === 200 || (res.status >= 200 && res.status < 300 && raw === ""));

  return {
    ok,
    status: res.status,
    detail: ok ? "" : (pickDetail(data) || `Unauthorized (HTTP ${res.status})`),
    data,
  };
}

export async function createAccount(token, payload) {
  const t = trimToken(token);
  if (!t) throw new Error("Empty token");

  const url = `${API_BASE}/api/create`;

  let out;
  try {
    out = await requestJson(
      url,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${t}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload || {}),
      },
      180000 // create kadang lama, kasih 3 menit
    );
  } catch (e) {
    throw new Error(`Network error: ${e?.message || e}`);
  }

  const { res, data } = out;

  if (!res.ok) {
    const msg = pickDetail(data) || `HTTP ${res.status}`;
    throw new Error(msg);
  }

  return data;
}