"""The phone companion: what the PC offers the JARVIS Android app.

Nothing here is reachable until the user switches the phone link on. Then a
SECOND, small web app (this module's `app`) listens on the PC's Tailscale
address only, never on the main API port and never on every interface:
Tailscale already encrypts and authenticates the network, and this adds a
per-phone token on top. Only a phone paired with a one-time code can call it.

What a paired phone can do: ask JARVIS something, search and download files
from the folders he is allowed to search, relay a message to whoever is near
the PC (and carry their spoken reply back), see his status and press Unlock.
What it cannot do, even by asking him: run commands, open terminals or
browsers, start builds, or drive other apps (see REMOTE_BLOCKED).

There is deliberately no silent listening: a relay is announced with a chime
and spoken aloud, and the room's reply is the next sentence the microphone
hears, once, after that announcement.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import ipaddress
import logging
import os
import re
import secrets
import subprocess
import time
import uuid
from collections import OrderedDict
from pathlib import Path
from typing import Awaitable, Callable, Optional

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

import toolkit

log = logging.getLogger("jarvis.companion")

PORT_DEFAULT = 8341
PAIR_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
PAIR_TTL_SEC = 300
PAIR_MAX_TRIES = 5
FAIL_LIMIT, FAIL_WINDOW = 10, 300
REPLY_WAIT_SEC = 45
MAX_BYTES = 100 * 1024 * 1024
MAX_MESSAGES = 100
SEND_EXTS = {".svg", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".pdf", ".dxf", ".dwg", ".ai",
             ".eps", ".lbrn", ".lbrn2", ".gcode", ".nc", ".txt", ".csv", ".md", ".doc", ".docx",
             ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".3mf", ".stl", ".step", ".stp", ".xcs"}

# Tools a request from the phone may not use, whatever the brain decides.
REMOTE_BLOCKED = {"run_command", "spawn_run", "start_build", "steer_session", "answer_dialog",
                  "fix_yourself", "open_in_terminal", "open_in_browser", "open_in_editor",
                  "desktop_ui", "browse", "routine", "voice_mode", "create_project",
                  "approve_document", "enable_session_inbox", "voice_lock"}


class Hooks:
    """Filled in by server.py."""
    turn: Optional[Callable[[str], Awaitable[str]]] = None
    speak_room: Optional[Callable[[str, bool], Awaitable[bool]]] = None   # audible in the room?
    chime: Optional[Callable[[], Awaitable[None]]] = None
    status: Callable[[], dict] = staticmethod(lambda: {})


remote_active = 0
_messages: list[dict] = []
_next_id = 1
_awaiting: dict = {}
_pairing: dict = {}
_fails: dict[str, list] = {}
_files: "OrderedDict[str, Path]" = OrderedDict()
listener: dict = {"server": None, "task": None, "address": None, "error": None}


# ── devices ────────────────────────────────────────────────────────────────

def _devices() -> dict:
    return toolkit.load_json("devices", {})


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_pairing_code() -> dict:
    code = "".join(secrets.choice(PAIR_ALPHABET) for _ in range(8))
    _pairing.update(code=code, expires=time.time() + PAIR_TTL_SEC, tries=0)
    return {"code": f"{code[:4]}-{code[4:]}", "expires_in": PAIR_TTL_SEC}


def pairing_active() -> Optional[dict]:
    if _pairing.get("code") and _pairing["expires"] > time.time():
        return {"code": f"{_pairing['code'][:4]}-{_pairing['code'][4:]}",
                "expires_in": int(_pairing["expires"] - time.time())}
    return None


def redeem(code: str, name: str) -> Optional[str]:
    """A new device token if `code` is the live pairing code, else None."""
    if not _pairing.get("code") or _pairing["expires"] <= time.time():
        return None
    _pairing["tries"] = _pairing.get("tries", 0) + 1
    if _pairing["tries"] > PAIR_MAX_TRIES:
        _pairing.clear()
        return None
    norm = re.sub(r"[^A-Za-z0-9]", "", code or "").upper()
    if not hmac.compare_digest(norm.encode(), _pairing["code"].encode()):
        return None
    _pairing.clear()
    token = secrets.token_urlsafe(32)
    devices = _devices()
    devices[uuid.uuid4().hex[:8]] = {"name": toolkit.clean(name, 40) or "Phone", "hash": _hash(token),
                                     "created": time.time(), "last_seen": time.time()}
    toolkit.save_json("devices", devices)
    return token


def authenticate(token: str) -> Optional[dict]:
    if not token:
        return None
    digest = _hash(token)
    devices = _devices()
    for did, d in devices.items():
        if hmac.compare_digest(d.get("hash", ""), digest):
            if time.time() - d.get("last_seen", 0) > 60:
                d["last_seen"] = time.time()
                toolkit.save_json("devices", devices)
            return {"id": did, "name": d.get("name", "Phone")}
    return None


def revoke(key: str) -> int:
    devices = _devices()
    gone = [i for i, d in devices.items() if key == i or key.lower() in d.get("name", "").lower()]
    for i in gone:
        devices.pop(i)
    toolkit.save_json("devices", devices)
    return len(gone)


def device_list() -> list[dict]:
    return [{"id": i, "name": d.get("name", "Phone"), "last_seen": d.get("last_seen", 0)}
            for i, d in _devices().items()]


# ── the gate: what a request from the phone may not do ─────────────────────

def gate(tool: str) -> Optional[str]:
    if remote_active and tool in REMOTE_BLOCKED:
        return "not_from_the_phone — that one I only do when you're at the PC, sir."
    return None


toolkit.add_gate(gate)


@contextlib.asynccontextmanager
async def remote_request():
    global remote_active
    remote_active += 1
    try:
        yield
    finally:
        remote_active -= 1


# ── files ──────────────────────────────────────────────────────────────────

def file_problem(path: Path) -> Optional[str]:
    from features import filefinder
    try:
        rp = path.resolve()
    except OSError:
        return "gone"
    if not rp.is_file():
        return "gone"
    if rp.suffix.lower() not in SEND_EXTS:
        return "That kind of file isn't one I send."
    if not filefinder.inside_roots(rp):
        return "That file isn't in a folder I'm allowed to search."
    try:
        if rp.stat().st_size > MAX_BYTES:
            return "That file is over 100 MB."
    except OSError:
        return "gone"
    return None


def register_file(path: Path) -> str:
    fid = uuid.uuid4().hex[:12]
    _files[fid] = path
    while len(_files) > 400:
        _files.popitem(last=False)
    return fid


def describe(fid: str, path: Path) -> dict:
    try:
        st = path.stat()
        return {"id": fid, "name": path.name, "folder": path.parent.name, "size": st.st_size,
                "modified": int(st.st_mtime)}
    except OSError:
        return {"id": fid, "name": path.name, "folder": "", "size": 0, "modified": 0}


def search_files(query: str, kind: str = "", limit: int = 30) -> list[dict]:
    from features import filefinder
    q = toolkit.clean(query, 80)
    found = filefinder.search(q, kind, 0, limit=limit, only_exts=SEND_EXTS)
    return [describe(register_file(p), p) for p in found if file_problem(p) is None]


def queue_for_phone(path: Path) -> tuple[Optional[dict], Optional[str]]:
    """Put a file in the outbox the phone's Files tab shows."""
    problem = file_problem(path)
    if problem:
        return None, problem
    fid = register_file(path.resolve())
    entry = {**describe(fid, path.resolve()), "queued": time.time()}
    outbox = [e for e in toolkit.load_json("outbox", []) if time.time() - e.get("queued", 0) < 86400]
    outbox.append(entry)
    toolkit.save_json("outbox", outbox[-40:])
    return entry, None


# ── relay ──────────────────────────────────────────────────────────────────

def add_message(sender: str, text: str) -> dict:
    global _next_id
    msg = {"id": _next_id, "from": sender, "text": toolkit.clean(text, 400), "at": int(time.time())}
    _next_id += 1
    _messages.append(msg)
    del _messages[:-MAX_MESSAGES]
    return msg


async def relay(text: str, label: str = "", wait_reply: bool = False, urgent: bool = False) -> dict:
    text = toolkit.clean(text, 400)
    if not text:
        return {"delivered": False, "reason": "empty"}
    if Hooks.speak_room is None:
        return {"delivered": False, "reason": "not ready"}
    who = toolkit.clean(label, 30) or "your phone"
    if Hooks.chime:
        try:
            await Hooks.chime()
        except Exception:
            pass
    ok = await Hooks.speak_room(f"Message from {who}: {text}", urgent)
    if not ok:
        return {"delivered": False, "reason": "Nobody can hear the PC right now — open JARVIS "
                                               "on it, or check the speakers."}
    if wait_reply:
        _awaiting.update(until=time.time() + REPLY_WAIT_SEC, label=who)
    return {"delivered": True, "waiting": bool(wait_reply)}


async def capture_reply(text: str) -> Optional[str]:
    """Interceptor: the first thing heard after a relay is the room's reply."""
    if _awaiting.get("until", 0) > time.time() and text.strip():
        _awaiting.clear()
        add_message("room", text)
        try:
            from features import phone
            await phone.push("Reply: " + toolkit.clean(text, 200), "JARVIS relay")
        except Exception:
            pass
        if Hooks.speak_room:
            await Hooks.speak_room("Passed that on.", False)
        return None
    return text


async def expire_reply() -> None:
    if _awaiting and _awaiting.get("until", 0) <= time.time():
        _awaiting.clear()
        add_message("jarvis", "No one answered.")


toolkit.add_interceptor(capture_reply, first=True)
toolkit.register_job(toolkit.Job("relay-expiry", 5.0, expire_reply))


# ── the web app ────────────────────────────────────────────────────────────

app = FastAPI(title="JARVIS companion", docs_url=None, redoc_url=None, openapi_url=None)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def _note_fail(ip: str) -> None:
    row = _fails.setdefault(ip, [0, time.time()])
    if time.time() - row[1] > FAIL_WINDOW:
        row[:] = [0, time.time()]
    row[0] += 1


def _throttled(ip: str) -> bool:
    row = _fails.get(ip)
    return bool(row and time.time() - row[1] <= FAIL_WINDOW and row[0] >= FAIL_LIMIT)


async def require_device(request: Request) -> dict:
    ip = _client_ip(request)
    if _throttled(ip):
        raise HTTPException(status_code=429, detail="too many attempts")
    header = request.headers.get("authorization", "")
    dev = authenticate(header[7:] if header.startswith("Bearer ") else "")
    if dev is None:
        _note_fail(ip)
        raise HTTPException(status_code=401, detail="not paired")
    return dev


class PairBody(BaseModel):
    code: str
    name: str = "Phone"


class SayBody(BaseModel):
    text: str


class RelayBody(BaseModel):
    text: str
    label: str = ""
    wait_reply: bool = False
    urgent: bool = False


class UnlockBody(BaseModel):
    minutes: float = 10


@app.post("/pair")
async def pair(body: PairBody, request: Request):
    ip = _client_ip(request)
    if _throttled(ip):
        raise HTTPException(status_code=429, detail="too many attempts")
    token = redeem(body.code, body.name)
    if token is None:
        _note_fail(ip)
        raise HTTPException(status_code=403, detail="that code is wrong or has expired")
    from features import phone
    return {"token": token, "ntfy_topic": phone.topic() or None}


@app.get("/status")
async def status(dev: dict = Depends(require_device)):
    from features import lock
    return {"ok": True, "device": dev["name"], "time": int(time.time()), "lock": lock.status(),
            **Hooks.status()}


@app.post("/say")
async def say(body: SayBody, dev: dict = Depends(require_device)):
    text = toolkit.clean(body.text, 1000)
    if not text:
        raise HTTPException(status_code=400, detail="empty")
    if Hooks.turn is None:
        raise HTTPException(status_code=503, detail="JARVIS isn't ready")
    async with remote_request():
        try:
            reply = await asyncio.wait_for(Hooks.turn(text), 150)
        except asyncio.TimeoutError:
            raise HTTPException(status_code=504, detail="he took too long")
    return {"reply": (reply or "").strip()[:2000] or "Done, sir."}


@app.get("/files/search")
async def files_search(q: str = "", kind: str = "", dev: dict = Depends(require_device)):
    if not q.strip() and not kind:
        return {"files": []}
    return {"files": await asyncio.to_thread(search_files, q, kind)}


@app.get("/files/outbox")
async def files_outbox(dev: dict = Depends(require_device)):
    keep = []
    for e in toolkit.load_json("outbox", []):
        p = _files.get(e["id"])
        if p is not None and file_problem(p) is None and time.time() - e.get("queued", 0) < 86400:
            keep.append(e)
    return {"files": keep}


@app.get("/files/get/{fid}")
async def files_get(fid: str, dev: dict = Depends(require_device)):
    path = _files.get(fid)
    if path is None:
        raise HTTPException(status_code=404, detail="ask again — that link has expired")
    problem = file_problem(path)
    if problem:
        raise HTTPException(status_code=404 if problem == "gone" else 403, detail=problem)
    return FileResponse(str(path), filename=path.name)


@app.post("/relay")
async def relay_route(body: RelayBody, dev: dict = Depends(require_device)):
    return await relay(body.text, body.label or dev["name"], body.wait_reply, body.urgent)


@app.get("/messages")
async def messages(after: int = 0, dev: dict = Depends(require_device)):
    rows = [m for m in _messages if m["id"] > after]
    return {"messages": rows, "last": _messages[-1]["id"] if _messages else 0,
            "waiting": bool(_awaiting)}


@app.post("/unlock")
async def unlock(body: UnlockBody, dev: dict = Depends(require_device)):
    from features import lock
    lock.unlock(body.minutes)
    return lock.status()


@app.post("/lock")
async def lock_route(dev: dict = Depends(require_device)):
    from features import lock
    lock.lock_now()
    return lock.status()


# ── the listener ───────────────────────────────────────────────────────────

TAILSCALE_NET = ipaddress.ip_network("100.64.0.0/10")


def _tailscale_cli() -> list[str]:
    import shutil
    for cand in (shutil.which("tailscale"), r"C:\Program Files\Tailscale\tailscale.exe"):
        if cand and Path(cand).exists():
            return [cand]
    return []


def detect_tailscale_ip() -> Optional[str]:
    """This PC's Tailscale IPv4 address, or None if Tailscale isn't there."""
    cli = _tailscale_cli()
    if cli:
        try:
            out = subprocess.run([*cli, "ip", "-4"], capture_output=True, text=True, timeout=6).stdout
            for line in out.split():
                if ipaddress.ip_address(line) in TAILSCALE_NET:
                    return line
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    try:
        cmd = ["ipconfig"] if os.name == "nt" else ["ip", "-4", "addr"]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=6).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for m in re.finditer(r"\b(100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3})\b", out):
        try:
            if ipaddress.ip_address(m.group(1)) in TAILSCALE_NET:
                return m.group(1)
        except ValueError:
            continue
    return None


def enabled() -> bool:
    return bool(toolkit.load_json("companion", {}).get("enabled"))


def set_enabled(on: bool) -> None:
    toolkit.save_json("companion", {"enabled": bool(on)})


def bind_address() -> tuple[Optional[str], Optional[str]]:
    """(host, why-not). JARVIS_COMPANION_HOST overrides detection (e.g. a LAN
    address) for people who do not use Tailscale; 0.0.0.0 is refused."""
    forced = os.environ.get("JARVIS_COMPANION_HOST", "").strip()
    if forced:
        try:
            ip = ipaddress.ip_address(forced)
        except ValueError:
            return None, "JARVIS_COMPANION_HOST isn't an IP address"
        if ip.is_unspecified:
            return None, "JARVIS_COMPANION_HOST must be one specific address, not every interface"
        return forced, None
    ts = detect_tailscale_ip()
    if ts:
        return ts, None
    return None, "Tailscale isn't running on this PC. Install it from tailscale.com and sign in."


class _QuietServer(uvicorn.Server):
    """Run inside the main process without touching its signal handlers."""

    def install_signal_handlers(self) -> None:           # uvicorn < 0.29
        pass

    @contextlib.contextmanager
    def capture_signals(self):                            # uvicorn >= 0.29
        yield


def port() -> int:
    try:
        return int(os.environ.get("JARVIS_COMPANION_PORT", PORT_DEFAULT))
    except ValueError:
        return PORT_DEFAULT


async def start_listener() -> dict:
    await stop_listener()
    if not enabled():
        return status_info()
    host, why = bind_address()
    if host is None:
        listener.update(error=why, address=None)
        return status_info()
    server = _QuietServer(uvicorn.Config(app, host=host, port=port(), log_level="warning",
                                         access_log=False, lifespan="off"))
    task = asyncio.create_task(server.serve(), name="companion-listener")
    for _ in range(40):                                   # up to ~4 s to come up or fail
        await asyncio.sleep(0.1)
        if server.started or task.done():
            break
    if task.done() or not server.started:
        err = "couldn't start"
        if task.done() and not task.cancelled() and task.exception():
            err = f"couldn't listen on {host}:{port()} ({task.exception()})"
        server.should_exit = True
        listener.update(server=None, task=None, address=None,
                        error=err + " — is the port already in use?")
        return status_info()
    listener.update(server=server, task=task, address=f"{host}:{port()}", error=None)
    log.info("phone link listening on %s:%s", host, port())
    return status_info()


async def stop_listener() -> None:
    server, task = listener.get("server"), listener.get("task")
    if server is not None:
        server.should_exit = True
    if task is not None:
        try:
            await asyncio.wait_for(task, 5)
        except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
            task.cancel()
    listener.update(server=None, task=None, address=None)


def status_info() -> dict:
    return {"enabled": enabled(), "address": listener.get("address"), "error": listener.get("error"),
            "devices": device_list(), "pairing": pairing_active(),
            "tailscale": detect_tailscale_ip() if enabled() and not listener.get("address") else None}
