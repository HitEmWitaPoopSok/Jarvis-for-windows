"""Find files on the user's own folders, and open one with its default app."""
import os
import time
from pathlib import Path

import toolkit

SKIP_DIRS = {"node_modules", ".git", "__pycache__", "appdata", "$recycle.bin", ".venv", "venv"}
MAX_SCAN, MAX_HITS, DEADLINE = 40000, 15, 4.0
KINDS = {"pdf": {".pdf"}, "doc": {".doc", ".docx", ".odt", ".txt", ".md", ".rtf"},
         "sheet": {".xls", ".xlsx", ".csv", ".ods"}, "image": {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"},
         "video": {".mp4", ".mov", ".mkv", ".avi"}, "audio": {".mp3", ".wav", ".flac", ".m4a"},
         "slides": {".ppt", ".pptx", ".key"}, "zip": {".zip", ".7z", ".rar"},
         "svg": {".svg"}, "png": {".png"}, "vector": {".svg", ".dxf", ".ai", ".eps", ".dwg"},
         "laser": {".svg", ".dxf", ".lbrn", ".lbrn2", ".ai", ".eps", ".png", ".jpg", ".jpeg",
                   ".bmp", ".gcode", ".nc", ".xcs"},
         "3d": {".stl", ".3mf", ".step", ".stp"}, "xcs": {".xcs"}}
# Never opened by voice: anything that runs or installs.
OPEN_BLOCKED = {".exe", ".bat", ".cmd", ".ps1", ".msi", ".vbs", ".js", ".jse", ".wsf", ".lnk",
                ".scr", ".com", ".reg", ".hta", ".jar", ".py", ".sh"}


# Folders the user may add by voice must not be (or contain) these.
FORBIDDEN_PARTS = {"windows", "program files", "program files (x86)", "programdata", "appdata",
                   ".ssh", ".aws", ".gnupg", ".config", "system32", "$recycle.bin"}


def user_roots() -> list[Path]:
    return [Path(p) for p in toolkit.load_json("file_roots", []) if isinstance(p, str)]


def roots() -> list[Path]:
    home = Path(os.environ.get("USERPROFILE") or Path.home())
    base = [p for p in (home / "Documents", home / "Downloads", home / "Desktop") if p.is_dir()]
    return base + [p for p in user_roots() if p.is_dir()]


def check_new_root(raw: str):
    """(Path, None) if `raw` may become a search folder, else (None, why)."""
    p = Path(str(raw).strip().strip('"'))
    if not p.is_absolute() or not p.is_dir():
        return None, "That has to be a full path to a folder that exists"
    rp = p.resolve()
    if len(rp.parts) < 3 and os.name == "nt" or len(rp.parts) < 2:
        return None, "That's a whole drive — pick a specific folder"
    home = Path(os.environ.get("USERPROFILE") or Path.home()).resolve()
    if rp == home or rp in home.parents:
        return None, "That's your whole user folder — pick a folder inside it"
    # Inside the profile only the parts below it count (the profile itself may sit under a
    # folder with a forbidden name, e.g. a temp directory); elsewhere every part counts.
    below = rp.relative_to(home).parts if home in rp.parents else rp.parts
    if any(part.lower() in FORBIDDEN_PARTS for part in below):
        return None, "I won't search system or credential folders"
    return rp, None


def add_root(raw: str):
    p, why = check_new_root(raw)
    if p is None:
        return why
    cur = toolkit.load_json("file_roots", [])
    if str(p) not in cur:
        if len(cur) >= 12:
            return "That's as many folders as I can watch"
        cur.append(str(p))
        toolkit.save_json("file_roots", cur)
    return None


def remove_root(raw: str) -> bool:
    cur = toolkit.load_json("file_roots", [])
    keep = [c for c in cur if raw.lower() not in c.lower()]
    toolkit.save_json("file_roots", keep)
    return len(keep) != len(cur)


def search(query: str, kind: str = "", days: int = 0, limit: int = MAX_HITS,
           only_exts=None) -> list[Path]:
    words = [w for w in query.lower().split() if w]
    exts = KINDS.get(kind.lower())
    cutoff = time.time() - days * 86400 if days else 0
    start, scanned, hits = time.time(), 0, []
    for root in roots():
        for dirpath, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS and not d.startswith(".")]
            if dirpath[len(str(root)):].count(os.sep) > 5:
                dirs[:] = []
            for f in files:
                scanned += 1
                if scanned > MAX_SCAN or time.time() - start > DEADLINE:
                    return _best(hits, limit)
                low = f.lower()
                if words and not all(w in low for w in words):
                    continue
                if exts and Path(f).suffix.lower() not in exts:
                    continue
                if only_exts and Path(f).suffix.lower() not in only_exts:
                    continue
                p = Path(dirpath) / f
                try:
                    m = p.stat().st_mtime
                except OSError:
                    continue
                if m >= cutoff:
                    hits.append((m, p))
    return _best(hits, limit)


def _best(hits, limit=MAX_HITS):
    return [p for _, p in sorted(hits, reverse=True)[:limit]]


def inside_roots(p: Path) -> bool:
    try:
        rp = p.resolve()
    except OSError:
        return False
    return any(rp == r.resolve() or r.resolve() in rp.parents for r in roots())


def handler(args: dict) -> str:
    action = str(args.get("action") or "find").lower()
    if action == "find":
        query = toolkit.clean(args.get("query"), 80)
        kind = str(args.get("kind") or "")
        if not query and not kind:
            return "What am I looking for, sir?"
        found = search(query, kind, int(args.get("days") or 0))
        if not found:
            return "I found nothing like that in your folders, sir."
        return "\n".join(f"{i + 1}. {p}" for i, p in enumerate(found))
    if action == "open":
        raw = str(args.get("path") or "")
        p = Path(raw)
        if not p.is_absolute() or not p.is_file() or not inside_roots(p):
            return "I can only open files in the folders I search, sir."
        if p.suffix.lower() in OPEN_BLOCKED or not p.suffix:
            return "I won't launch that kind of file, sir — open it yourself."
        try:
            os.startfile(str(p))                      # noqa: Windows only
        except (AttributeError, OSError):
            return "I couldn't open that, sir."
        return "Opening it, sir."
    return "I can find or open files, sir."


toolkit.register(toolkit.Tool(
    name="find_files",
    description=("Search the user's Documents, Downloads and Desktop by file name "
                 "(never contents), newest first: `find` with `query` words, "
                 "optional `kind` (pdf, doc, sheet, image, video, audio, slides, "
                 "zip, svg, png, vector, laser, 3d, xcs) and `days` (modified within). `open` takes a full path "
                 "returned by a find, and opens it with its normal app; it will "
                 "not launch programs or scripts."),
    schema={"type": "object", "properties": {
        "action": {"type": "string", "enum": ["find", "open"]}, "query": {"type": "string"},
        "kind": {"type": "string"}, "days": {"type": "integer"}, "path": {"type": "string"}},
        "required": ["action"]},
    handler=handler, acting=True, reading=True, taint="file names on your computer", wrap=True))
