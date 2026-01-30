// endpoint.js
// Kalau panel di subdomain: https://panel.domain.tld/panel/...
// Kalau panel di domain utama: https://domain.tld/panel/...
window.YINN_PANEL = {
  // Base path untuk API panel:
  API_BASE: "/panel",

  // Endpoint auth verify (harus ada di app.py):
  VERIFY_PATH: "/api/auth/verify",

  // Endpoint create:
  CREATE_PATH: "/api/create",

  // Endpoint health (opsional, buat indikator):
  HEALTH_PATH: "/health",
};