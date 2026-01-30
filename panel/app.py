import os
import re
import subprocess
from typing import Optional, Literal

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

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{1,32}$")

MAX_OUT = 16000
MAX_HEAD = 9000
MAX_TAIL = 7000

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# noise lines seen in your output
NOISE_SUBSTR = [
    "unknown': I need something more specific.",
    '"unknown": I need something more specific.',
    "I need something more specific.",
]
NOISE_RE = re.compile(r"unknown['\"]?\s*:\s*I need something more specific\.", re.IGNORECASE)
LOADING_RE = re.compile(r"^\s*loading\.\.\.\s*$", re.IGNORECASE)

ADDSSH_DIR_ERR_RE = re.compile(r"^/usr/local/sbin/addssh:.*Is a directory\s*$", re.IGNORECASE)

# banners / headers we want to remove
BANNER_KEYWORDS = [
    "Cretae SSH Ovpn Account",
    "Create SSH Ovpn Account",
    "CREATE VMESS ACCOUNT",
    "CREATE VLESS ACCOUNT",
    "CREATE TROJAN ACCOUNT",
]
# decorative line patterns (your scripts print a lot of these)
DECOR_RE = re.compile(r"^[\s\W]*(☉|∘|○|o|•|═|—|_|=|-|–|━|─|·|\.){6,}[\s\W]*$")


class CreateReq(BaseModel):
    proto: str = Field(..., description="ssh/vmess/vless/trojan")
    username: str
    password: str = ""  # SSH only
    iplimit: int = 0
    days: int = 1
    quota_gb: int = 0  # XRAY only (0 = unlimited if your script supports)


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


def _strip_ansi(s: str) -> str:
    s = (s or "").replace("\r", "")
    return ANSI_RE.sub("", s)


def _trim_output(out: str) -> str:
    out = (out or "").strip()
    if len(out) <= MAX_OUT:
        return out
    head = out[:MAX_HEAD].rstrip()
    tail = out[-MAX_TAIL:].lstrip()
    return head + "\n\n... (trimmed) ...\n\n" + tail


def _build_stdin(proto: str, username: str, password: str, iplimit: int, days: int, quota_gb: int) -> bytes:
    p = (proto or "").lower().strip()

    if p == "ssh":
        # SSH: username, password, iplimit, days
        return f"{username}\n{password}\n{iplimit}\n{days}\n".encode()

    # XRAY: username, days, quota_gb, iplimit  (urutannya sesuai script lu)
    if p in ("vmess", "vless", "trojan"):
        return f"{username}\n{days}\n{quota_gb}\n{iplimit}\n".encode()

    return b""


def _clean_output(proto: str, raw: str) -> str:
    """
    CLEAN mode:
    - remove ANSI + weird carriage returns
    - remove spam 'unknown: I need something more specific.'
    - remove 'loading...' lines
    - remove /usr/local/sbin/addssh directory warning line
    - remove banner blocks like "CREATE VMESS ACCOUNT" / "Create SSH Ovpn Account"
    - keep the real result (status box + account details)
    """
    text = _strip_ansi(raw)
    lines = [ln.rstrip() for ln in text.split("\n")]

    cleaned: list[str] = []
    skip_next_blank_after_banner = False

    for ln in lines:
        s = ln.strip()

        # drop empty repeated lines but keep structure later
        if not s:
            if skip_next_blank_after_banner:
                continue
            cleaned.append("")
            continue

        # drop known noise
        if any(x in ln for x in NOISE_SUBSTR) or NOISE_RE.search(ln):
            continue
        if LOADING_RE.match(ln):
            continue

        # drop addssh warning line
        if ADDSSH_DIR_ERR_RE.match(ln):
            continue

        # drop banner keywords and their decorative neighbors
        if any(k.lower() in ln.lower() for k in BANNER_KEYWORDS):
            skip_next_blank_after_banner = True
            continue
        if DECOR_RE.match(ln):
            # only drop decor if it looks like a banner divider
            continue

        skip_next_blank_after_banner = False
        cleaned.append(ln)

    # remove leading/trailing empty lines
    while cleaned and not cleaned[0].strip():
        cleaned.pop(0)
    while cleaned and not cleaned[-1].strip():
        cleaned.pop()

    # collapse 3+ blank lines to max 2
    out2: list[str] = []
    blank_run = 0
    for ln in cleaned:
        if ln.strip() == "":
            blank_run += 1
            if blank_run <= 2:
                out2.append("")
        else:
            blank_run = 0
            out2.append(ln)

    return "\n".join(out2).strip()


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


@app.post("/api/create")
def create(
    req: CreateReq,
    authorization: Optional[str] = Header(default=None),
    mode: Literal["clean", "raw"] = "clean",
):
    if not auth_ok(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")

    proto = (req.proto or "").lower().strip()
    if proto not in CMD_MAP:
        raise HTTPException(status_code=400, detail="Invalid proto")

    username = (req.username or "").strip()
    if not USERNAME_RE.match(username):
        raise HTTPException(status_code=400, detail="Invalid username")

    iplimit = int(req.iplimit)
    if iplimit < 0 or iplimit > 50:
        raise HTTPException(status_code=400, detail="Invalid iplimit")

    days = int(req.days)
    if days < 1 or days > 365:
        raise HTTPException(status_code=400, detail="Invalid days")

    quota_gb = int(req.quota_gb)
    if quota_gb < 0 or quota_gb > 100000:
        raise HTTPException(status_code=400, detail="Invalid quota_gb")

    password = (req.password or "").strip()

    # SSH only: password required (min 1)
    if proto == "ssh":
        if len(password) < 1 or len(password) > 64:
            raise HTTPException(status_code=400, detail="Invalid password")
    else:
        password = ""  # hard reset (XRAY doesn't use password)

    cmd = CMD_MAP[proto]
    stdin_payload = _build_stdin(proto, username, password, iplimit, days, quota_gb)

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

    raw_out = p.stdout.decode(errors="replace")
    out = raw_out if mode == "raw" else _clean_output(proto, raw_out)

    out = _trim_output(out)

    if p.returncode != 0:
        # show last part of output for debug
        tail = (out or raw_out or "")[-1200:]
        raise HTTPException(status_code=500, detail=f"Command failed: {tail}")

    return {
        "ok": True,
        "mode": mode,
        "output": out,
    }