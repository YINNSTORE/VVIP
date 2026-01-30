import os
import re
import subprocess
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field

app = FastAPI(title="Yinn Panel API", version="1.0.0")

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


def auth_ok(authorization: Optional[str]) -> bool:
    if not API_TOKEN or not authorization:
        return False
    parts = authorization.split()
    return len(parts) == 2 and parts[0].lower() == "bearer" and parts[1] == API_TOKEN


def clean_output(s: str) -> str:
    # strip ANSI escapes (biar output lebih bersih)
    s = re.sub(r"\x1b\[[0-9;]*m", "", s)
    s = s.replace("\r", "")
    return s.strip()


@app.get("/health")
def health():
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

    # autoscript input: Username, Password, Limit IP, Expired (Days)
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

    out = clean_output(p.stdout.decode(errors="replace"))

    if p.returncode != 0:
        raise HTTPException(status_code=500, detail=f"Command failed: {out[-1200:]}")

    # limit output size
    return {"ok": True, "output": out[-6000:]}