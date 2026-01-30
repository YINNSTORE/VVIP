import os
import re
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

import pexpect

app = FastAPI(title="Yinn Panel API")

API_TOKEN = os.getenv("PANEL_TOKEN", "").strip()

CMD_MAP = {
    "ssh": "/usr/local/sbin/addssh",
    "vmess": "/usr/local/sbin/addws",
    "vless": "/usr/local/sbin/addvless",
    "trojan": "/usr/local/sbin/addtr",
}

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,32}$")


class CreateReq(BaseModel):
    proto: str = Field(..., description="ssh/vmess/vless/trojan")
    username: str
    password: str
    iplimit: int = 0
    days: int = 1


def _get_bearer(authorization: Optional[str]) -> str:
    if not authorization:
        return ""
    parts = authorization.strip().split()
    if len(parts) != 2:
        return ""
    if parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()


def auth_ok(authorization: Optional[str]) -> bool:
    token = _get_bearer(authorization)
    return bool(API_TOKEN) and bool(token) and token == API_TOKEN


@app.get("/")
def root():
    return RedirectResponse(url="/docs")


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/api/auth")
def auth_check(authorization: Optional[str] = Header(default=None)):
    if not auth_ok(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"ok": True}


@app.get("/api/auth")
def auth_check_get(authorization: Optional[str] = Header(default=None)):
    if not auth_ok(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"ok": True}


def run_autoscript(cmd_path: str, username: str, password: str, iplimit: int, days: int) -> str:
    """
    Jalankan autoscript interaktif via pexpect.
    Ini lebih tahan banting buat script addws/addvless/addtr yang prompt-nya beda-beda.
    """
    child = pexpect.spawn(f"sudo -n {cmd_path}", encoding="utf-8", timeout=180)

    out_chunks = []

    def expect_send(patterns, send_value: str):
      idx = child.expect(patterns)
      out_chunks.append(child.before or "")
      if send_value is not None:
        child.sendline(str(send_value))
      return idx

    # Pola prompt umum (berbeda tiap autoscript)
    PROMPT_USER = [r"Username", r"User", r"Masukkan.*user", r"Input.*user", r"Enter.*user", r"[Uu]sername"]
    PROMPT_PASS = [r"Password", r"Pass", r"Masukkan.*pass", r"Input.*pass", r"Enter.*pass"]
    PROMPT_IPL  = [r"Limit\s*IP", r"ip\s*limit", r"Max\s*IP", r"Device", r"limit.*device"]
    PROMPT_DAYS = [r"Expired", r"Days", r"Durasi", r"Masa\s*aktif", r"Berapa.*hari"]
    PROMPT_ANY  = [r"\?", r":", r">", r"\]"]

    # Kita loop: tangkap prompt, kirim input yang relevan
    # Stop kalau script selesai (EOF)
    sent_user = sent_pass = sent_ipl = sent_days = False

    while True:
      try:
        idx = child.expect(
          [
            pexpect.EOF,
            *PROMPT_USER,
            *PROMPT_PASS,
            *PROMPT_IPL,
            *PROMPT_DAYS,
          ],
          timeout=180,
        )

        if idx == 0:
          out_chunks.append(child.before or "")
          break

        matched = child.after or ""
        out_chunks.append(matched)

        m = matched.lower()

        if any(k.lower() in m for k in ["user", "username"]) and not sent_user:
          child.sendline(username); sent_user = True; continue

        if any(k.lower() in m for k in ["pass"]) and not sent_pass:
          child.sendline(password); sent_pass = True; continue

        if ("limit" in m or "device" in m) and not sent_ipl:
          child.sendline(str(iplimit)); sent_ipl = True; continue

        if ("expired" in m or "days" in m or "durasi" in m or "masa" in m) and not sent_days:
          child.sendline(str(days)); sent_days = True; continue

        # kalau prompt aneh: biarin (jangan spam input random)
        # kita cuma collect output
        continue

      except pexpect.TIMEOUT:
        out_chunks.append("\n[ERROR] timeout waiting autoscript prompt\n")
        break

    try:
      child.close()
    except Exception:
      pass

    return "".join(out_chunks).strip()


@app.post("/api/create")
def create(req: CreateReq, authorization: Optional[str] = Header(default=None)):
    if not auth_ok(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")

    proto = (req.proto or "").lower().strip()
    if proto not in CMD_MAP:
        raise HTTPException(status_code=400, detail="Invalid proto")

    username = (req.username or "").strip()
    if not USERNAME_RE.match(username):
        raise HTTPException(status_code=400, detail="Invalid username")

    password = (req.password or "").strip()
    if len(password) < 4 or len(password) > 64:
        raise HTTPException(status_code=400, detail="Invalid password")

    iplimit = int(req.iplimit)
    if iplimit < 0 or iplimit > 50:
        raise HTTPException(status_code=400, detail="Invalid iplimit")

    days = int(req.days)
    if days < 1 or days > 365:
        raise HTTPException(status_code=400, detail="Invalid days")

    cmd = CMD_MAP[proto]

    out = run_autoscript(cmd, username, password, iplimit, days)

    # kalau autoscript ngasih error besar, lempar 500
    if re.search(r"PERMISSION DENIED|Banned|404 NOT FOUND|Unauthorized", out, re.I):
        raise HTTPException(status_code=500, detail=out[-2000:])

MAX_HEAD = 20000
MAX_TAIL = 80000

head = out[:MAX_HEAD]
tail = out[-MAX_TAIL:] if len(out) > MAX_TAIL else out
merged = head + ("\n\n... (trimmed) ...\n\n" if len(out) > (MAX_HEAD + MAX_TAIL) else "\n") + tail

return {"ok": True, "output": merged, "trimmed": len(out) > (MAX_HEAD + MAX_TAIL)}