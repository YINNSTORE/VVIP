// endpoint.js (robust)
export const API_BASE = ""; 
// kosong = same-origin (panel.domain), jadi aman

async function safeJson(res) {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch (e) {
    return { _raw: text };
  }
}

export async function verifyToken(token) {
  const t = (token || "").trim();
  if (!t) return { ok: false, status: 0, detail: "Empty token" };

  const res = await fetch(`${API_BASE}/api/auth`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${t}`,
      "Accept": "application/json",
    },
  });

  const data = await safeJson(res);

  // ✅ aturan valid paling toleran:
  // - status 2xx
  // - dan salah satu field ok/success/valid true
  // - kalau tidak ada field, tapi status 200, tetap anggap OK
  const okFlag =
    data?.ok === true ||
    data?.success === true ||
    data?.valid === true ||
    data?.authorized === true;

  const ok = res.ok && (okFlag || res.status === 200);

  return {
    ok,
    status: res.status,
    data,
  };
}

export async function createAccount(token, payload) {
  const t = (token || "").trim();
  const res = await fetch(`${API_BASE}/api/create`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${t}`,
      "Content-Type": "application/json",
      "Accept": "application/json",
    },
    body: JSON.stringify(payload || {}),
  });

  const data = await safeJson(res);

  if (!res.ok) {
    const msg = (data && (data.detail || data.error)) || `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return data;
}