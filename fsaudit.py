"""Local filesystem audit for a project folder: walks every sub-folder and file looking for
risky file types (archives, executables, DB dumps, keys, leftover debug scripts...), flags an
exposed .git/.svn folder on sight, and builds the full file list of the public web root so every
one of those files can be checked for direct web access. Read-only - never writes or deletes anything.
"""
from __future__ import annotations

import os
import time

DANGEROUS_EXT = {
    ".exe": ("executable", "critical"), ".msi": ("executable", "critical"), ".dll": ("executable", "high"),
    ".bat": ("executable", "high"), ".cmd": ("executable", "high"), ".ps1": ("executable", "high"), ".sh": ("executable", "medium"),
    ".jar": ("executable", "medium"), ".apk": ("executable", "high"), ".dmg": ("executable", "high"), ".iso": ("archive", "medium"),
    ".zip": ("archive", "high"), ".rar": ("archive", "high"), ".7z": ("archive", "high"), ".tar": ("archive", "medium"), ".gz": ("archive", "medium"),
    ".sql": ("database_dump", "critical"), ".sqlite": ("database_dump", "critical"), ".sqlite3": ("database_dump", "critical"),
    ".db": ("database_dump", "critical"), ".mdb": ("database_dump", "critical"), ".accdb": ("database_dump", "critical"),
    ".bak": ("backup", "critical"), ".old": ("backup", "high"), ".orig": ("backup", "medium"), ".swp": ("backup", "low"),
    ".save": ("backup", "medium"), ".tmp": ("backup", "low"), ".backup": ("backup", "high"), ".copy": ("backup", "medium"),
    ".pem": ("credential_key", "critical"), ".key": ("credential_key", "critical"), ".p12": ("credential_key", "critical"),
    ".pfx": ("credential_key", "critical"), ".ppk": ("credential_key", "critical"), ".crt": ("credential_key", "medium"),
    ".log": ("log", "medium"), ".csv": ("data_export", "low"), ".xls": ("data_export", "low"), ".xlsx": ("data_export", "low"),
    ".inc": ("sensitive_config", "medium"), ".ini": ("sensitive_config", "medium"), ".conf": ("sensitive_config", "medium"),
    ".config": ("sensitive_config", "medium"), ".yml": ("sensitive_config", "low"), ".yaml": ("sensitive_config", "low"),
    ".map": ("source_map", "medium"), ".pcap": ("data_export", "high"), ".dump": ("database_dump", "critical"),
}
SENSITIVE_NAMES = {
    "db.php": ("database_dump", "critical"), "database.php": ("database_dump", "critical"), ".env": ("credential_key", "critical"),
    ".env.local": ("credential_key", "critical"), ".env.backup": ("credential_key", "critical"), "config.php": ("sensitive_config", "high"),
    "settings.php": ("sensitive_config", "high"), "local.xml": ("sensitive_config", "high"), "wp-config.php": ("sensitive_config", "critical"),
    "database_analysis.php": ("debug_script", "high"), "phpinfo.php": ("debug_script", "high"), "info.php": ("debug_script", "high"),
    "test.php": ("debug_script", "medium"), "debug.php": ("debug_script", "medium"), "thumbs.db": ("os_metadata", "low"),
    ".ds_store": ("os_metadata", "low"), "web.config": ("sensitive_config", "medium"), ".htpasswd": ("credential_key", "critical"),
    ".htaccess": ("sensitive_config", "low"), "id_rsa": ("credential_key", "critical"), "id_dsa": ("credential_key", "critical"),
    "credentials.json": ("credential_key", "critical"), "secrets.json": ("credential_key", "critical"),
}
SKIP_DIR_NAMES = {"node_modules", "__pycache__", ".idea", ".vscode"}
REPO_DIR_NAMES = {".git", ".svn", ".hg"}
# noisy, genuinely-benign dev tooling that lives inside vendor/bin - skip to keep the report meaningful
VENDOR_BIN_ALLOW = {"phpunit", "psalm", "phpstan", "php-cs-fixer", "yii", "composer", "codecept", "phpcbf", "phpcs"}

MAX_FILES = 150_000
MAX_FINDINGS = 600
MAX_WEB_FILES = 12000         # cap on the full web-root sweep list (still huge; keeps the HTTP pass sane)
MAX_WEB_DIRS = 4000
TIME_BUDGET_S = 90

# file extension -> (group label, severity-when-directly-served). Severity None = benign/expected public asset.
FILE_TYPES: dict[str, tuple[str, str | None]] = {}
def _reg(exts, label, sev):
    for e in exts.split():
        FILE_TYPES[e] = (label, sev)
_reg("php phtml php3 php4 php5 phps inc module", "Source Code (PHP)", "high")      # should execute, never be downloadable as source
_reg("py rb pl cgi asp aspx jsp", "Source Code (script)", "high")
_reg("sql dump mdb accdb sqlite sqlite3 db", "Database", "critical")
_reg("env ini conf config cnf", "Config", "high")
_reg("yml yaml toml", "Config", "medium")
_reg("pem key ppk p12 pfx crt cer", "Key / Certificate", "critical")
_reg("zip rar 7z tar gz tgz bz2 war", "Archive", "high")
_reg("bak old orig save backup copy swp tmp", "Backup / Temp", "high")
_reg("exe msi dll bat cmd ps1 sh jar apk", "Executable", "critical")
_reg("log", "Log", "medium")
_reg("csv xls xlsx", "Data Export", "low")
_reg("json xml txt", "Data / Text", "low")
_reg("map", "Source Map", "medium")
_reg("md lock", "Project Metadata", "low")
_reg("js mjs ts jsx", "JavaScript", None)
_reg("css scss less", "Stylesheet", None)
_reg("png jpg jpeg gif svg webp ico bmp avif", "Image", None)
_reg("woff woff2 ttf eot otf", "Font", None)
_reg("mp4 webm mp3 wav ogg mov", "Media", None)
_reg("pdf doc docx ppt pptx", "Document", "low")
_reg("html htm", "HTML", None)


def file_type(name: str) -> tuple[str, str | None]:
    ext = os.path.splitext(name.lower())[1].lstrip(".")
    return FILE_TYPES.get(ext, ("Other", "low"))


def classify(name: str) -> tuple[str, str] | None:
    low = name.lower()
    if low in SENSITIVE_NAMES:
        return SENSITIVE_NAMES[low]
    ext = os.path.splitext(low)[1]
    if ext in DANGEROUS_EXT:
        return DANGEROUS_EXT[ext]
    return None


def walk_project(path: str) -> dict:
    if not path or not os.path.isdir(path):
        return {"ok": False, "error": "Folder not found on this machine.", "root": path}
    path = os.path.normpath(path)
    web_dir = os.path.join(path, "web")
    web_root = web_dir if os.path.isfile(os.path.join(web_dir, "index.php")) or os.path.isfile(os.path.join(web_dir, "index.html")) else None

    findings = []
    web_files = []         # every file under web_root (rel-web), for the full HTTP access sweep, capped
    web_dirs = []          # every directory under web_root (rel-web), for the listing/accessibility sweep
    all_files = []         # EVERY file in the whole project (rel to project root) - inside AND outside web/
    all_dirs = []          # EVERY directory in the whole project (rel to project root)
    listable_dirs = []     # directories with no index file (the only ones that could show a listing)
    n_files = n_dirs = 0
    t0 = time.time()
    truncated = {"v": False}
    probe_base = web_root or path     # the folder the web server most likely serves as docroot

    def process(dirpath, dirnames, filenames):
        nonlocal n_files, n_dirs
        for repo_dir in [d for d in dirnames if d.lower() in REPO_DIR_NAMES]:
            full = os.path.join(dirpath, repo_dir)
            rel_root = os.path.relpath(full, path).replace("\\", "/")
            rel_web = os.path.relpath(full, web_root).replace("\\", "/") if web_root and full.lower().startswith(web_root.lower()) else None
            findings.append({"rel_root": rel_root, "rel_web": rel_web, "in_web_root": rel_web is not None,
                             "category": "exposed_repo", "severity": "critical", "size": 0, "filename": repo_dir, "is_dir": True})
        dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIR_NAMES and d.lower() not in REPO_DIR_NAMES]
        n_dirs += 1
        in_probe = dirpath.lower().startswith(probe_base.lower())
        in_web = web_root and dirpath.lower().startswith(web_root.lower())
        in_vendor_bin = os.path.normpath(dirpath).replace("\\", "/").split("/")[-2:-1] == ["bin"] and "vendor" in dirpath.lower()
        if in_probe and dirpath.lower() != probe_base.lower() and len(web_dirs) < MAX_WEB_DIRS:
            rel = os.path.relpath(dirpath, probe_base).replace("\\", "/")
            web_dirs.append(rel + "/")
        if dirpath.lower() != path.lower() and len(all_dirs) < MAX_WEB_DIRS * 2:
            rel_d = os.path.relpath(dirpath, path).replace("\\", "/") + "/"
            all_dirs.append(rel_d)
            # a folder with an index file can never show a listing (the server runs the index instead),
            # so only folders WITHOUT one are worth probing for directory listing - and they respond fast
            if not any(fn.lower() in ("index.php", "index.html", "index.htm") for fn in filenames):
                listable_dirs.append(rel_d)
        for fn in filenames:
            n_files += 1
            full = os.path.join(dirpath, fn)
            rel_root = os.path.relpath(full, path).replace("\\", "/")
            if in_probe and len(web_files) < MAX_WEB_FILES:
                web_files.append(os.path.relpath(full, probe_base).replace("\\", "/"))
            if len(all_files) < MAX_WEB_FILES * 2:
                all_files.append(rel_root)
            if in_vendor_bin and os.path.splitext(fn)[0].lower() in VENDOR_BIN_ALLOW:
                continue
            hit = classify(fn)
            if not hit:
                continue
            category, severity = hit
            try:
                size = os.path.getsize(full)
            except OSError:
                size = 0
            rel_web = os.path.relpath(full, web_root).replace("\\", "/") if in_web else None
            findings.append({"rel_root": rel_root, "rel_web": rel_web, "in_web_root": rel_web is not None,
                             "category": category, "severity": severity, "size": size, "filename": fn, "is_dir": False})

    def walk(top, skip_abs=None):
        for dirpath, dirnames, filenames in os.walk(top, topdown=True):
            if time.time() - t0 > TIME_BUDGET_S or n_files > MAX_FILES:
                truncated["v"] = True
                return
            original = list(dirnames)   # unfiltered, so .git/.svn are still detected as findings
            dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIR_NAMES and d.lower() not in REPO_DIR_NAMES
                           and not (skip_abs and os.path.normpath(os.path.join(dirpath, d)).lower() == skip_abs)]
            process(dirpath, original, filenames)

    # walk the public web folder FIRST (it is the most important and alphabetically often last),
    # so a big vendor/ or node_modules never eats the budget before web/ is covered; then the rest.
    if web_root:
        walk(web_root)
    walk(path, skip_abs=os.path.normpath(web_root).lower() if web_root else None)
    truncated = truncated["v"]
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (not f["in_web_root"], sev_order.get(f["severity"], 4)))
    return {
        "ok": True, "root": path, "web_root": web_root, "probe_base": probe_base,
        "files_scanned": n_files, "dirs_scanned": n_dirs,
        "truncated": truncated, "findings": findings[:MAX_FINDINGS], "findings_total": len(findings),
        "web_files": web_files, "web_files_total_seen": len(web_files),
        "web_dirs": web_dirs, "web_dirs_total_seen": len(web_dirs),
        "all_files": all_files, "all_dirs": all_dirs, "listable_dirs": listable_dirs,
    }


def candidate_urls(result: dict, limit: int = 300) -> dict[str, tuple[str, str]]:
    """Build {relative_url_path: (severity, reason)} to feed into the HTTP exposure probe -
    covers findings outside the public web root (config/, vendor/, runtime/...), since the full
    web-root tree is checked file-by-file separately via web_files()."""
    out: dict[str, tuple[str, str]] = {}
    if not result.get("ok"):
        return out
    reason_by_cat = {
        "executable": "An executable file was found in the project folder - should never be reachable over the web.",
        "archive": "An archive file was found in the project folder - could leak source code/assets if downloaded.",
        "database_dump": "A database file/dump was found in the project folder - may contain real data and credentials.",
        "backup": "A backup/leftover file was found in the project folder.",
        "credential_key": "A credential/key file was found in the project folder.",
        "log": "A log file was found in the project folder - may leak paths, queries or stack traces.",
        "data_export": "A data export file was found in the project folder.",
        "sensitive_config": "An application config file was found in the project folder - may contain credentials.",
        "debug_script": "A leftover debug/diagnostic script was found in the project folder.",
        "os_metadata": "An OS metadata file was found - low risk, but indicates the folder itself is reachable.",
        "source_map": "A source map was found - can reveal original, unminified source code.",
        "exposed_repo": "A version-control folder (.git/.svn) was found - if reachable, the entire source history can be downloaded.",
    }
    for f in result["findings"]:
        reason = reason_by_cat.get(f["category"], "Potentially sensitive file.")
        probe = f["rel_root"] + ("/HEAD" if f["category"] == "exposed_repo" and not f["rel_root"].endswith("HEAD") else "")
        out.setdefault(probe, (f["severity"], reason))
        if f["rel_web"]:
            probe_w = f["rel_web"] + ("/HEAD" if f["category"] == "exposed_repo" and not f["rel_web"].endswith("HEAD") else "")
            out.setdefault(probe_w, (f["severity"], reason))
        if len(out) >= limit:
            break
    return dict(list(out.items())[:limit])


def web_root_files(result: dict) -> list[str]:
    """Every file found under the detected public web root, for the full file-by-file HTTP sweep."""
    if not result.get("ok"):
        return []
    return result.get("web_files", [])


def web_root_dirs(result: dict) -> list[str]:
    """Every directory under the detected public web root, for the listing/accessibility sweep."""
    if not result.get("ok"):
        return []
    return result.get("web_dirs", [])


def project_files(result: dict) -> list[str]:
    """Every file in the whole project (rel to project root) - inside AND outside web/."""
    return result.get("all_files", []) if result.get("ok") else []


def project_dirs(result: dict) -> list[str]:
    """Every directory in the whole project (rel to project root)."""
    return result.get("all_dirs", []) if result.get("ok") else []


def listable_project_dirs(result: dict) -> list[str]:
    """Only directories that could actually show a listing (no index file) - the fast, worthwhile ones to probe."""
    return result.get("listable_dirs", []) if result.get("ok") else []
