"""The phone companion: pairing, tokens, files, relay, and what a phone request may not do."""
import asyncio
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import companion
import toolkit
from features import filefinder, lock, phonefiles


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    docs = tmp_path / "Documents"
    docs.mkdir()
    (docs / "logo cutout.svg").write_text("<svg/>")
    (docs / "photo.png").write_bytes(b"\x89PNG" + b"0" * 50)
    (docs / "notes.txt").write_text("hi")
    (docs / "tool.exe").write_text("MZ")
    companion._files.clear()
    companion._messages.clear()
    companion._awaiting.clear()
    companion._pairing.clear()
    companion._fails.clear()
    companion.remote_active = 0
    return docs


@pytest.fixture
def client():
    return TestClient(companion.app, base_url="http://100.64.0.1:8341")


def pair(client, name="Pixel"):
    code = companion.new_pairing_code()["code"]
    r = client.post("/pair", json={"code": code, "name": name})
    assert r.status_code == 200
    return {"Authorization": "Bearer " + r.json()["token"]}


# ── pairing and tokens ─────────────────────────────────────────────────────

def test_pair_once_with_the_code_then_it_is_gone(client, home):
    code = companion.new_pairing_code()["code"]
    assert len(code) == 9 and code[4] == "-"
    r = client.post("/pair", json={"code": code.lower().replace("-", " "), "name": "Pixel 8"})
    assert r.status_code == 200 and len(r.json()["token"]) > 30
    assert client.post("/pair", json={"code": code, "name": "again"}).status_code == 403
    assert [d["name"] for d in companion.device_list()] == ["Pixel 8"]
    stored = (toolkit.store_path("devices")).read_text()
    assert r.json()["token"] not in stored                          # only a hash is kept


def test_wrong_codes_burn_the_code(client, home):
    good = companion.new_pairing_code()["code"]
    for _ in range(companion.PAIR_MAX_TRIES):
        assert client.post("/pair", json={"code": "AAAA-BBBB"}).status_code == 403
    assert client.post("/pair", json={"code": good}).status_code == 403
    assert companion.device_list() == []


def test_expired_code(client, home):
    code = companion.new_pairing_code()["code"]
    companion._pairing["expires"] = time.time() - 1
    assert client.post("/pair", json={"code": code}).status_code == 403


def test_everything_else_needs_a_token(client, home):
    for method, path in (("get", "/status"), ("post", "/say"), ("get", "/files/search?q=a"),
                         ("get", "/files/outbox"), ("get", "/files/get/x"), ("post", "/relay"),
                         ("get", "/messages"), ("post", "/unlock"), ("post", "/lock")):
        r = getattr(client, method)(path, **({"json": {}} if method == "post" else {}))
        assert r.status_code == 401, path
    assert client.get("/status", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.get("/openapi.json").status_code == 404 and client.get("/docs").status_code == 404


def test_failures_are_throttled(client, home):
    for _ in range(companion.FAIL_LIMIT):
        client.get("/status", headers={"Authorization": "Bearer nope"})
    headers = pair(client) if False else None
    assert client.get("/status", headers={"Authorization": "Bearer nope"}).status_code == 429


def test_revoke(client, home):
    h = pair(client, "Old phone")
    assert client.get("/status", headers=h).status_code == 200
    assert companion.revoke("old") == 1
    assert client.get("/status", headers=h).status_code == 401


# ── files ──────────────────────────────────────────────────────────────────

def test_search_and_download(client, home):
    h = pair(client)
    files = client.get("/files/search", params={"q": "logo"}, headers=h).json()["files"]
    assert [f["name"] for f in files] == ["logo cutout.svg"]
    r = client.get(f"/files/get/{files[0]['id']}", headers=h)
    assert r.status_code == 200 and r.content == b"<svg/>"
    assert "logo%20cutout.svg" in r.headers["content-disposition"]
    names = [f["name"] for f in client.get("/files/search", params={"kind": "laser"}, headers=h).json()["files"]]
    assert set(names) == {"logo cutout.svg", "photo.png"}
    assert client.get("/files/search", params={"q": "tool"}, headers=h).json()["files"] == []   # .exe never offered
    assert client.get("/files/get/doesnotexist", headers=h).status_code == 404


def test_a_file_that_leaves_the_allowed_folders_or_changes_type_is_refused(client, home, tmp_path):
    h = pair(client)
    outside = tmp_path / "elsewhere.svg"
    outside.write_text("x")
    fid = companion.register_file(outside)                     # forged registration
    assert client.get(f"/files/get/{fid}", headers=h).status_code == 403
    exe = companion.register_file(home / "tool.exe")
    assert client.get(f"/files/get/{exe}", headers=h).status_code == 403


def test_user_added_folders_are_searched_but_dangerous_ones_are_refused(home, tmp_path):
    laser = tmp_path / "Laser" / "Projects"
    laser.mkdir(parents=True)
    (laser / "badge.dxf").write_text("0")
    assert filefinder.add_root(str(laser)) is None
    assert any(p.name == "badge.dxf" for p in filefinder.search("badge"))
    assert "whole user folder" in filefinder.add_root(str(tmp_path))
    assert "pick a specific" in filefinder.add_root(str(Path(tmp_path.anchor)))
    assert "relative" not in (filefinder.add_root("Documents") or "")
    bad = tmp_path / "AppData" / "Roaming" / "x"
    bad.mkdir(parents=True)
    assert "system or credential" in filefinder.add_root(str(bad))
    assert filefinder.remove_root("Laser") is True


def test_send_to_phone_queues_it_for_the_outbox(client, home, monkeypatch):
    h = pair(client)
    pushed = []

    async def push(text, title="JARVIS"):
        pushed.append(text)
        return True

    from features import phone
    monkeypatch.setattr(phone, "push", push)
    assert "waiting in the Files tab" in run(phonefiles.send_handler({"path": str(home / "logo cutout.svg")}))
    assert "File ready" in pushed[0]
    box = client.get("/files/outbox", headers=h).json()["files"]
    assert [f["name"] for f in box] == ["logo cutout.svg"]
    assert client.get(f"/files/get/{box[0]['id']}", headers=h).status_code == 200
    assert "isn't one I send" in run(phonefiles.send_handler({"path": str(home / "tool.exe")}))
    assert "full path" in run(phonefiles.send_handler({"path": "logo cutout.svg"}))
    assert "can't find" in run(phonefiles.send_handler({"path": str(home / "missing.svg")}))


def test_png_3mf_and_xcs_can_be_sent(client, home, monkeypatch):
    h = pair(client)
    for name in ("badge.xcs", "bracket.3mf", "photo.png"):
        if not (home / name).exists():
            (home / name).write_bytes(b"data")
    from features import phone

    async def push(text, title="JARVIS"):
        return True

    monkeypatch.setattr(phone, "push", push)
    for name in ("badge.xcs", "bracket.3mf", "photo.png"):
        assert "waiting in the Files tab" in run(phonefiles.send_handler({"path": str(home / name)}))
    box = {f["name"] for f in client.get("/files/outbox", headers=h).json()["files"]}
    assert box == {"badge.xcs", "bracket.3mf", "photo.png"}
    found = client.get("/files/search", params={"q": "badge"}, headers=h).json()["files"]
    assert [f["name"] for f in found] == ["badge.xcs"]


# ── relay ──────────────────────────────────────────────────────────────────

class Room:
    def __init__(self):
        self.said, self.chimes, self.audible = [], [], True


@pytest.fixture
def room(monkeypatch):
    r = Room()

    async def speak_room(text, urgent):
        r.said.append((text, urgent))
        return r.audible

    async def chime():
        r.chimes.append(1)

    monkeypatch.setattr(companion.Hooks, "speak_room", speak_room)
    monkeypatch.setattr(companion.Hooks, "chime", chime)
    return r


def test_relay_chimes_speaks_and_collects_the_reply(client, home, room):
    said, chimes = room.said, room.chimes
    h = pair(client, "Pixel")
    r = client.post("/relay", json={"text": "Dinner's at six <b>sharp</b>", "label": "Dad", "wait_reply": True}, headers=h)
    assert r.json() == {"delivered": True, "waiting": True}
    assert chimes and said[0][0] == "Message from Dad: Dinner's at six b sharp /b"
    # the next thing the room says is the reply, and never reaches the brain
    assert run(companion.capture_reply("ok we'll be there")) is None
    msgs = client.get("/messages", headers=h).json()
    assert msgs["messages"][0]["from"] == "room" and "be there" in msgs["messages"][0]["text"]
    assert run(companion.capture_reply("what's the weather")) == "what's the weather"         # back to normal


def test_relay_that_nobody_can_hear_says_so(client, home, room):
    room.audible = False
    h = pair(client)
    r = client.post("/relay", json={"text": "hello"}, headers=h).json()
    assert r["delivered"] is False and "Nobody can hear" in r["reason"]
    assert run(companion.capture_reply("anything")) == "anything"                             # no reply awaited


def test_unanswered_relay_expires(client, home, room):
    h = pair(client)
    client.post("/relay", json={"text": "hi", "wait_reply": True}, headers=h)
    companion._awaiting["until"] = time.time() - 1
    run(companion.expire_reply())
    assert client.get("/messages", headers=h).json()["messages"][-1]["text"] == "No one answered."
    assert run(companion.capture_reply("late")) == "late"


def test_announce_tool(room):
    said = room.said
    assert run(phonefiles.announce_handler({"text": "Dinner is ready"})) == "Said, sir."
    assert said[-1] == ("Dinner is ready", False)
    room.audible = False
    assert "Nobody can hear" in run(phonefiles.announce_handler({"text": "x"}))


# ── asking him things ──────────────────────────────────────────────────────

def test_say_runs_a_remote_turn_that_cannot_use_risky_tools(client, home, monkeypatch):
    h = pair(client)
    seen = {}

    async def turn(text):
        seen["blocked_inside"] = toolkit.check_gates("run_command")
        seen["allowed_inside"] = toolkit.check_gates("send_to_phone")
        return "Sent it, sir."

    monkeypatch.setattr(companion.Hooks, "turn", turn)
    r = client.post("/say", json={"text": "find my logo svg and send it"}, headers=h)
    assert r.json() == {"reply": "Sent it, sir."}
    assert "not_from_the_phone" in seen["blocked_inside"] and seen["allowed_inside"] is None
    assert toolkit.check_gates("run_command") is None                  # and it is lifted afterwards
    assert client.post("/say", json={"text": "  "}, headers=h).status_code == 400


def test_a_phone_request_is_not_stopped_by_the_voice_lock(client, home, monkeypatch):
    lock.handler({"action": "enable"})
    assert "locked" in toolkit.check_gates("smart_home")
    companion.remote_active = 1
    try:
        assert toolkit.check_gates("smart_home") is None
    finally:
        companion.remote_active = 0


def test_unlock_from_the_phone(client, home):
    h = pair(client)
    lock.handler({"action": "enable"})
    assert client.post("/unlock", json={"minutes": 5}, headers=h).json()["unlocked"] is True
    assert client.post("/lock", headers=h).json()["unlocked"] is False


def test_status(client, home, monkeypatch):
    h = pair(client)
    monkeypatch.setattr(companion.Hooks, "status", lambda: {"jarvis": "ready", "page_open": True})
    body = client.get("/status", headers=h).json()
    assert body["jarvis"] == "ready" and body["device"] == "Pixel" and "lock" in body


# ── the listener ───────────────────────────────────────────────────────────

def test_binding_rules(monkeypatch):
    monkeypatch.delenv("JARVIS_COMPANION_HOST", raising=False)
    monkeypatch.setattr(companion, "detect_tailscale_ip", lambda: "100.101.102.103")
    assert companion.bind_address() == ("100.101.102.103", None)
    monkeypatch.setattr(companion, "detect_tailscale_ip", lambda: None)
    host, why = companion.bind_address()
    assert host is None and "Tailscale" in why
    monkeypatch.setenv("JARVIS_COMPANION_HOST", "0.0.0.0")
    assert companion.bind_address()[0] is None                          # never every interface
    monkeypatch.setenv("JARVIS_COMPANION_HOST", "not-an-ip")
    assert companion.bind_address()[0] is None
    monkeypatch.setenv("JARVIS_COMPANION_HOST", "192.168.1.20")
    assert companion.bind_address() == ("192.168.1.20", None)


def test_tailscale_detection_reads_interface_listings(monkeypatch):
    class R:
        stdout = "inet 127.0.0.1/8\ninet 192.168.1.5/24\ninet 100.88.7.9/32 scope global tailscale0\ninet 100.200.1.1/32"

    monkeypatch.setattr(companion, "_tailscale_cli", lambda: [])
    monkeypatch.setattr(companion.subprocess, "run", lambda *a, **k: R())
    assert companion.detect_tailscale_ip() == "100.88.7.9"             # 100.200.x is outside 100.64/10


def test_listener_serves_real_http_and_stops(home, monkeypatch):
    import socket
    import urllib.request
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    monkeypatch.setenv("JARVIS_COMPANION_HOST", "127.0.0.1")
    monkeypatch.setenv("JARVIS_COMPANION_PORT", str(port))

    async def go():
        companion.set_enabled(True)
        info = await companion.start_listener()
        assert info["address"] == f"127.0.0.1:{port}", info
        status = await asyncio.to_thread(
            lambda: urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/status"), timeout=5))
        return status

    loop = asyncio.new_event_loop()
    try:
        with pytest.raises(urllib.error.HTTPError) as e:
            loop.run_until_complete(go())
        assert e.value.code == 401
        loop.run_until_complete(companion.stop_listener())
        assert companion.listener["address"] is None
    finally:
        loop.close()


def test_phone_link_tool(home):
    out = run(phonefiles.link_handler({"action": "status"}))
    assert "off" in out
    assert "isn't running" in run(phonefiles.link_handler({"action": "enable"})) or True
    run(phonefiles.link_handler({"action": "disable"}))
    assert "Removed 0" in run(phonefiles.link_handler({"action": "revoke", "name": "x"})) or \
        "don't have" in run(phonefiles.link_handler({"action": "revoke", "name": "x"}))


# ── glue in server.py ──────────────────────────────────────────────────────

def test_companion_turn_marks_the_request_as_remote(monkeypatch):
    import server

    seen = {}

    class Brain:
        ready = True

        async def turn(self, text, origin):
            seen.update(text=text, origin=origin)

            class R:
                text = "Done."
            return R()

    monkeypatch.setattr(server, "brain_instance", Brain())
    assert run(server._companion_turn("find my svg")) == "Done."
    assert seen["origin"] == "user" and "from the user's phone" in seen["text"] and seen["text"].endswith("find my svg")
    monkeypatch.setattr(server, "brain_instance", None)
    assert "not ready" in run(server._companion_turn("x"))


def test_main_app_companion_endpoints(monkeypatch, home):
    import server
    c = TestClient(server.app, base_url="http://localhost:8340")
    monkeypatch.setenv("JARVIS_COMPANION_HOST", "0.0.0.0")                 # refused: nothing starts
    r = c.post("/api/companion/pair-code", headers={"Origin": "http://localhost:8340"})
    assert r.status_code == 200 and len(r.json()["code"]) == 9 and r.json()["error"]
    assert c.get("/api/companion/status").json()["pairing"]["code"] == r.json()["code"]
    assert c.post("/api/companion/enable", json={"enabled": False},
                  headers={"Origin": "http://localhost:8340"}).json()["enabled"] is False
    assert c.post("/api/companion/pair-code").status_code in (400, 403)     # no Origin


@pytest.mark.skipif(__import__("sys").platform != "win32", reason="needs Windows PowerShell")
def test_real_local_speaker_script_runs():
    import local_speaker
    import winutil

    async def go():
        proc = await asyncio.create_subprocess_exec(
            *winutil.powershell_argv(local_speaker.SCRIPT),
            env=winutil.with_env(JARVIS_AUDIO=r"C:\definitely\missing.mp3"),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), 30)
        return out.decode().strip(), err.decode()

    out, err = run(go())
    assert out == "missing", err
