"""Tools that work with the Android companion: send a file to the phone, speak to the
room, choose which folders may be searched, and manage the phone link.

`companion` is imported inside each handler, so the brain's MCP child (which only
needs the tool descriptions) never loads the web stack.
"""
from pathlib import Path

import toolkit
from features import filefinder


async def send_handler(args: dict) -> str:
    import companion
    p = Path(str(args.get("path") or ""))
    if not p.is_absolute():
        return "Give me the full path from the search, sir."
    entry, problem = companion.queue_for_phone(p)
    if problem:
        return ("I can't find that file any more, sir." if problem == "gone" else problem + ", sir.")
    try:
        from features import phone
        await phone.push(f"File ready: {entry['name']} — open JARVIS > Files.", "JARVIS")
    except Exception:
        pass
    return f"{entry['name']} is waiting in the Files tab of your phone app, sir."


async def announce_handler(args: dict) -> str:
    import companion
    text = toolkit.clean(args.get("text"), 300)
    if not text:
        return "What shall I say, sir?"
    if companion.Hooks.speak_room is None:
        return "I can't speak just now, sir."
    ok = await companion.Hooks.speak_room(text, bool(args.get("urgent")))
    return "Said, sir." if ok else "Nobody can hear the PC just now, sir — the speakers or the page are off."


def folders_handler(args: dict) -> str:
    action = str(args.get("action") or "list").lower()
    if action == "list":
        mine = filefinder.user_roots()
        base = [str(p) for p in filefinder.roots() if p not in mine]
        return "I search: " + "; ".join(base + [str(p) for p in mine]) + "."
    path = str(args.get("path") or "")
    if action == "add":
        why = filefinder.add_root(path)
        return f"{why}, sir." if why else "Added — I'll look there too, sir."
    if action == "remove":
        return "Removed, sir." if filefinder.remove_root(path) else "That wasn't one of the folders you added, sir."
    return "I can add, remove or list folders, sir."


async def link_handler(args: dict) -> str:
    import companion
    action = str(args.get("action") or "status").lower()
    if action in ("enable", "disable"):
        companion.set_enabled(action == "enable")
        info = await companion.start_listener() if action == "enable" else (await companion.stop_listener() or companion.status_info())
        if action == "enable":
            if info.get("error"):
                return f"Phone link is on but not listening, sir: {info['error']}"
            return "Phone link is on, sir. Press Pair a phone on my display to link one."
        return "Phone link is off, sir."
    if action == "revoke":
        n = companion.revoke(toolkit.clean(args.get("name"), 40))
        return f"Removed {n} phone{'s' if n != 1 else ''}, sir." if n else "I don't have a phone like that, sir."
    if action == "status":
        info = companion.status_info()
        if not info["enabled"]:
            return "The phone link is off, sir."
        names = ", ".join(d["name"] for d in info["devices"]) or "none paired"
        where = info["address"] or f"not listening ({info['error']})"
        return f"The phone link is on at {where}. Phones: {names}."
    return "I can enable, disable, revoke or give the status, sir."


toolkit.register(toolkit.Tool(
    name="send_to_phone",
    description=("Send a file from the PC to the user's phone: take a full `path` returned by "
                 "find_files and it appears in the Files tab of the JARVIS app (and a push "
                 "says so). Works for documents, images (SVG, PNG, JPG and so on), vector and "
                 "laser project files (SVG, DXF, LightBurn, xTool .xcs), G-code and 3D models "
                 "(STL, 3MF, STEP), under 100 MB, from the folders you search. Do not refuse "
                 "a file for its type yourself: call this and it reports if the type is not "
                 "allowed. Use after the user asks you to "
                 "find and send something, e.g. the SVG for their engraving."),
    schema={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
    handler=send_handler, acting=True, exempt="it sends one file the user chose, only to their paired phone"))
toolkit.register(toolkit.Tool(
    name="announce",
    description=("Say something aloud on the PC's speakers for whoever is in the room — "
                 "'tell them dinner is ready'. `urgent` for something that can't wait."),
    schema={"type": "object", "properties": {"text": {"type": "string"}, "urgent": {"type": "boolean"}},
            "required": ["text"]},
    handler=announce_handler, acting=True, exempt="it speaks the user's own words and reads nothing"))
toolkit.register(toolkit.Tool(
    name="search_folders",
    description=("Which folders find_files searches: `list`, `add` a folder by full `path` (a "
                 "laser project folder, say) or `remove` one. Never a whole drive, the user "
                 "profile, or system/credential folders."),
    schema={"type": "object", "properties": {
        "action": {"type": "string", "enum": ["list", "add", "remove"]}, "path": {"type": "string"}},
        "required": ["action"]},
    handler=folders_handler, acting=True, exempt="it edits the user's own folder list"))
toolkit.register(toolkit.Tool(
    name="phone_link",
    description=("The link to the user's Android app: `status`, `enable`, `disable`, or "
                 "`revoke` a phone by name. Pairing is done by the user pressing 'Pair a "
                 "phone' on the display; never read a pairing code aloud."),
    schema={"type": "object", "properties": {
        "action": {"type": "string", "enum": ["status", "enable", "disable", "revoke"]},
        "name": {"type": "string"}}, "required": ["action"]},
    handler=link_handler, acting=True, exempt="it manages the user's own paired phones"))
