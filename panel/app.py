import os
import re
import subprocess
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

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


# ✅ VERIFY TOKEN (buat login web)
@app.post("/api/auth")
def auth_check(authorization: Optional[str] = Header(default=None)):
    if not auth_ok(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"ok": True}


# optional: kalau web lu ternyata pakai GET
@app.get("/api/auth")
def auth_check_get(authorization: Optional[str] = Header(default=None)):
    if not auth_ok(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"ok": True}


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
    stdin_payload = f"{username}\n{password}\n{iplimit}\n{days}\n".encode()

    try:
        p = subprocess.run(
            ["sudo", "-n", cmd],
            input=stdin_payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=180,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Command timeout")

    out = p.stdout.decode(errors="replace").strip()
    if p.returncode != 0:
        raise HTTPException(status_code=500, detail=f"Command failed: {out[-1200:]}")

    return {"ok": True, "output": out[-4000:]}