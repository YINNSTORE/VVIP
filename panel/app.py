import os
import re
import subprocess
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field
import hmac


app = FastAPI(title="Yinn Panel API")

API_TOKEN = os.getenv("PANEL_TOKEN", "").strip()

CMD_MAP = {
    "ssh": "/usr/local/sbin/addssh",
    "vmess": "/usr/local/sbin/addws",
    "vless": "/usr/local/sbin/addvless",
    "trojan": "/usr/local/sbin/addtr",
}

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,32}$")
ANSI_RE = re.compile(r"\x1B\[[0-9;]*[A-Za-z]")


class CreateReq(BaseModel):
    proto: str = Field(..., description="ssh/vmess/vless/trojan")
    username: str
    password: str
    iplimit: int = 0
    days: int = 1


def _clean_out(s: str) -> str:
    s = (s or "").replace("\r", "")
    s = ANSI_RE.sub("", s)
    return s.strip()


def auth_ok(authorization: Optional[str], x_panel_token: Optional[str] = None) -> bool:
    """
    Accept:
      - Authorization: Bearer <token>
      - OR X-Panel-Token: <token>
    """
    if not API_TOKEN:
        return False

    token = ""

    if authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1].strip()

    if not token and x_panel_token:
        token = x_panel_token.strip()

    if not token:
        return False

    # constant-time compare
    return hmac.compare_digest(token, API_TOKEN)


@app.get("/health")
def health():
    # public
    return {"ok": True}


@app.get("/api/auth/verify")
def verify_token(
    authorization: Optional[str] = Header(default=None),
    x_panel_token: Optional[str] = Header(default=None, convert_underscores=False),
):
    if not auth_ok(authorization, x_panel_token):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"ok": True}


@app.post("/api/auth")
def auth_check(
    authorization: Optional[str] = Header(default=None),
    x_panel_token: Optional[str] = Header(default=None, convert_underscores=False),
):
    # backward compatible
    if not auth_ok(authorization, x_panel_token):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"ok": True}


@app.get("/api/commands")
def commands(
    authorization: Optional[str] = Header(default=None),
    x_panel_token: Optional[str] = Header(default=None, convert_underscores=False),
) -> Dict[str, Any]:
    if not auth_ok(authorization, x_panel_token):
        raise HTTPException(status_code=401, detail="Unauthorized")

    def exists(path: str) -> bool:
        return os.path.exists(path) and os.access(path, os.X_OK)

    return {
        "ok": True,
        "commands": {k: {"path": v, "exists": exists(v)} for k, v in CMD_MAP.items()},
    }


@app.post("/api/create")
def create(
    req: CreateReq,
    authorization: Optional[str] = Header(default=None),
    x_panel_token: Optional[str] = Header(default=None, convert_underscores=False),
):
    if not auth_ok(authorization, x_panel_token):
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

    try:
        iplimit = int(req.iplimit)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid iplimit")
    if iplimit < 0 or iplimit > 50:
        raise HTTPException(status_code=400, detail="Invalid iplimit")

    try:
        days = int(req.days)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid days")
    if days < 1 or days > 365:
        raise HTTPException(status_code=400, detail="Invalid days")

    cmd = CMD_MAP[proto]

    # autoscript input: Username, Password, Limit IP, Expired (Days)
    stdin_payload = f"{username}\n{password}\n{iplimit}\n{days}\n".encode()

    try:
        p = subprocess.run(
            ["sudo", "-n", cmd],
            input=stdin_payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Command timeout")

    out = _clean_out(p.stdout.decode(errors="replace"))
    if p.returncode != 0:
        # kasih detail tapi dibatasi biar gak kebanyakan
        tail = out[-1600:] if len(out) > 1600 else out
        raise HTTPException(status_code=500, detail=f"Command failed (rc={p.returncode}): {tail}")

    # output dibatasi
    trimmed = out[-6000:] if len(out) > 6000 else out
    return {"ok": True, "returncode": p.returncode, "output": trimmed}