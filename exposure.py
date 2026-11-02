"""Unauthenticated exposure scan: common sensitive files/folders that should never be web-accessible.

Runs with a clean client (no session cookies) against the site root and, when given, the
app's base-URL folder - mirroring what any anonymous visitor or bot could reach.
"""
from __future__ import annotations

import asyncio
import re

import httpx

import fsaudit

# path -> (severity, why it matters)
PATHS: dict[str, tuple[str, str]] = {
    ".env": ("critical", "Environment file - often contains DB credentials and secret keys."),
    ".env.local": ("critical", "Environment file - often contains DB credentials and secret keys."),
    ".env.backup": ("critical", "Environment file backup."),
    ".git/config": ("critical", "Exposed Git repository - source code and history can be downloaded."),
    ".git/HEAD": ("critical", "Exposed Git repository - source code and history can be downloaded."),
    ".svn/entries": ("critical", "Exposed Subversion repository."),
    "config/db.php": ("critical", "Yii/PHP database config - may contain DB credentials."),
    "config/main.php": ("high", "Yii application config."),
    "config/web.php": ("high", "Yii 2 web config."),
    "config/params.php": ("medium", "Yii 2 app parameters."),
    "protected/config/main.php": ("critical", "Yii 1 config outside expected web root - may contain DB credentials."),
    "protected/config/database.php": ("critical", "Yii 1 database config."),
    "common/config/main-local.php": ("critical", "Yii 2 advanced template local config - may contain secrets."),
    "console/config/main-local.php": ("critical", "Yii 2 advanced template local config - may contain secrets."),
    "backend/config/main-local.php": ("critical", "Yii 2 advanced template local config - may contain secrets."),
    "frontend/config/main-local.php": ("critical", "Yii 2 advanced template local config - may contain secrets."),
    "yii": ("medium", "Yii console entry script should not be web-accessible."),
    "yii.bat": ("medium", "Yii console entry script should not be web-accessible."),
    "requirements.php": ("low", "Yii requirements checker leaks environment/version info."),
    "composer.json": ("medium", "Reveals installed packages and versions (helps attackers target known CVEs)."),
    "composer.lock": ("medium", "Reveals exact installed package versions."),
    "vendor/": ("high", "Composer vendor directory should not be web-accessible."),
    "vendor/autoload.php": ("high", "Composer vendor directory is web-accessible."),
    "runtime/": ("high", "Yii runtime directory (logs, cache) should not be web-accessible."),
    "runtime/logs/app.log": ("high", "Application log file exposed - may leak stack traces, paths, queries."),
    "runtime/logs/error.log": ("high", "Error log file exposed."),
    "migrations/": ("medium", "Database migration scripts should not be web-accessible."),
    "tests/": ("low", "Test directory should not be web-accessible."),
    ".idea/": ("medium", "IDE project files should not be web-accessible."),
    ".vscode/": ("low", "Editor config directory exposed."),
    ".DS_Store": ("low", "macOS metadata file can leak directory listings."),
    "web.config": ("medium", "IIS config file exposed."),
    "phpinfo.php": ("high", "phpinfo() output leaks full server configuration."),
    "info.php": ("high", "phpinfo() output leaks full server configuration."),
    "test.php": ("medium", "Leftover test/debug script."),
    "debug.php": ("medium", "Leftover debug script."),
    "backup.sql": ("critical", "Database backup exposed."),
    "database.sql": ("critical", "Database dump exposed."),
    "db.sql": ("critical", "Database dump exposed."),
    "backup.zip": ("high", "Backup archive exposed."),
    "backup.tar.gz": ("high", "Backup archive exposed."),
    "site.zip": ("high", "Site archive exposed."),
    "error_log": ("medium", "Server error log exposed."),
    "storage/": ("medium", "Storage directory should not be directly browsable."),
    ".htaccess": ("low", "Apache access rules exposed (usually harmless, but check for leaked rewrite logic)."),
    "server-status": ("medium", "Apache server-status page exposed - reveals live request details."),
    "elmah.axd": ("medium", "ELMAH error log viewer exposed."),
    "swagger.json": ("low", "API schema exposed - confirm this is intentional."),
    "api/swagger.json": ("low", "API schema exposed - confirm this is intentional."),
}
DIR_LISTING_RE = re.compile(r"(Index of /|<title>Index of|Directory Listing For|Parent Directory)", re.I)
SECRET_RE = re.compile(r"(DB_PASSWORD|DB_USER|password\s*=>|'password'|define\(\s*['\"]DB_|AWS_SECRET|API_KEY|SECRET_KEY)", re.I)


async def scan(origin: str, base_path: str | None = None, extra_paths: dict[str, tuple[str, str]] | None = None,
               emit=lambda e: None, bases: list[str] | None = None) -> list[dict]:
    o = origin.rstrip("/")
    roots = {o + "/"}
    if base_path:
        roots.add(o + "/" + base_path.strip("/") + "/")
    for b in (bases or []):
        roots.add(o + "/" + b.strip("/") + "/" if b.strip("/") else o + "/")
    all_paths: dict[str, tuple[str, str]] = {p: PATHS[p] for p in PATHS}
    for p, (sev, why) in (extra_paths or {}).items():
        all_paths[p] = (sev, why)
    sem_results = {}
    async with httpx.AsyncClient(verify=False, timeout=6, follow_redirects=False, headers={"User-Agent": "StressScope/1.0 (authorised exposure scan)"}) as c:
        sem = asyncio.Semaphore(40)

        async def check(root, path, default_sev, default_why):
            url = root + path
            async with sem:
                try:
                    r = await c.get(url)
                except Exception:  # noqa: BLE001
                    return
                if r.status_code >= 400 or r.status_code in (301, 302, 303, 307, 308):
                    return
                body = r.text[:4000] if not path.endswith("/") else r.text[:2000]
                is_listing = path.endswith("/") and DIR_LISTING_RE.search(body)
                has_secret_pattern = bool(SECRET_RE.search(body))
                if path.endswith("/") and not is_listing and len(body) < 40:
                    return   # likely a generic empty/blocked index, not a real listing
                sev = default_sev
                if has_secret_pattern:
                    sev = "critical"
                item = {"url": url, "path": path, "status": r.status_code, "severity": sev, "reason": default_why,
                       "size": len(r.content), "directory_listing": bool(is_listing), "contains_secret_pattern": has_secret_pattern}
                sem_results[url] = item
                emit({"type": "exposure_hit", "finding": item})

        await asyncio.gather(*(check(root, p, *all_paths[p]) for root in roots for p in all_paths))
    return sorted(sem_results.values(), key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}[x["severity"]])


PHP_SOURCE_RE = re.compile(r"^\s*<\?php", re.I)
PHP_EXTS = (".php", ".phtml", ".php3", ".php4", ".php5", ".inc")
ENTRY_SCRIPTS = {"index.php", "yii", "requirements.php", "yii.php"}


async def sweep_web_root(origin: str, base_path: str | None, files: list[str], emit=lambda e: None) -> dict:
    """Check EVERY file found under the project's public web root for direct access. Ordinary public
    assets are expected to be reachable and are not reported; this specifically catches PHP served as
    plain source (misconfigured handler), server errors, and anything flagged by the dangerous-file list."""
    if not files:
        return {"checked": 0, "findings": []}
    roots = {origin.rstrip("/") + "/"}
    if base_path:
        roots.add(origin.rstrip("/") + "/" + base_path.strip("/") + "/")
    findings: list[dict] = []
    checked = 0
    async with httpx.AsyncClient(verify=False, timeout=5, follow_redirects=False, headers={"User-Agent": "StressScope/1.0 (authorised exposure scan)"}) as c:
        sem = asyncio.Semaphore(50)

        async def check(root, path):
            nonlocal checked
            url = root + path
            async with sem:
                try:
                    r = await c.get(url)
                except Exception:  # noqa: BLE001
                    return
                checked += 1
                if r.status_code >= 400:
                    return
                name = path.rsplit("/", 1)[-1].lower()
                ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
                item = None
                if ext in PHP_EXTS and name not in ENTRY_SCRIPTS:
                    body = r.text[:300]
                    if PHP_SOURCE_RE.search(body):
                        item = {"url": url, "path": path, "status": r.status_code, "severity": "critical",
                               "reason": "PHP source code is served as plain text instead of being executed by the server - the full source (and any embedded credentials) is readable by anyone.",
                               "size": len(r.content), "directory_listing": False, "contains_secret_pattern": bool(SECRET_RE.search(body))}
                elif r.status_code >= 500:
                    item = {"url": url, "path": path, "status": r.status_code, "severity": "low",
                           "reason": "This file returned a server error when requested directly.", "size": len(r.content),
                           "directory_listing": False, "contains_secret_pattern": False}
                if item:
                    findings.append(item)
                    emit({"type": "exposure_hit", "finding": item})

        await asyncio.gather(*(check(root, f) for root in roots for f in files))
    return {"checked": checked, "findings": findings}


DIR_SENSITIVE_RE = re.compile(r"(config|vendor|runtime|logs?|backup|migrations?|tests?|node_modules|cache|tmp|temp|"
                              r"uploads?|private|secret|includes?|lib|src|protected|storage|db|sql)", re.I)


async def sweep_all(origin: str, base_path: str | None, dirs: list[str], files: list[str], emit=lambda e: None,
                    halted=lambda: False) -> dict:
    """Professional directory sweep: probe EVERY directory (is it browsable? does it exist?) and EVERY
    file (is it directly downloadable?) under the public web root, then group the reachable ones into
    clear categories. Benign public assets (js/css/images/fonts) are counted, not individually listed."""
    root = origin.rstrip("/") + "/"
    if base_path:
        root = origin.rstrip("/") + "/" + base_path.strip("/") + "/"
    accessible: list[dict] = []
    asset_counts: dict[str, int] = {}
    scanned: list[dict] = []          # every path probed, with its result (for the live feed + "all scanned" view)
    checked_files = checked_dirs = 0
    seen: set[str] = set()
    total = len(dirs) + len(files)

    def feed(path, status, kind, acc):
        n = len(scanned) + 1
        if len(scanned) < 40000:
            scanned.append({"path": path, "status": status, "kind": kind, "accessible": acc})
        if n % 15 == 0 or acc or n == total:   # throttle the live stream a little
            emit({"type": "dir_live", "n": n, "total": total, "path": path, "status": status, "kind": kind, "accessible": acc})

    async with httpx.AsyncClient(verify=False, timeout=4, follow_redirects=False,
                                 limits=httpx.Limits(max_connections=110, max_keepalive_connections=110),
                                 headers={"User-Agent": "StressScope/1.0 (authorised directory scan)"}) as c:
        sem = asyncio.Semaphore(100)

        def record(item):
            if item["url"] in seen:
                return
            seen.add(item["url"])
            accessible.append(item)
            emit({"type": "exposure_hit", "finding": item})

        async def probe_dir(path):
            nonlocal checked_dirs
            if halted():
                return
            url = root + path
            async with sem:
                try:
                    r = await c.get(url)
                except Exception:  # noqa: BLE001
                    feed(path, "ERR", "directory", False)
                    return
                checked_dirs += 1
                sensitive = bool(DIR_SENSITIVE_RE.search(path))
                acc = False
                if r.status_code == 200:
                    body = r.text[:3000]
                    listing = bool(DIR_LISTING_RE.search(body))
                    if listing:
                        acc = True
                        record({"url": url, "path": path, "status": 200, "kind": "directory", "listing": True,
                                "group": "Directory Listing", "ftype": "directory",
                                "severity": "critical" if sensitive else "high",
                                "reason": "Directory listing is enabled - anyone can browse and download every file in this folder."})
                elif r.status_code in (401, 403) and sensitive:
                    record({"url": url, "path": path, "status": r.status_code, "kind": "directory", "listing": False,
                            "group": "Protected Directory", "ftype": "directory", "severity": "info",
                            "reason": "Directory exists and is reachable but access is forbidden (good - confirms the path is present)."})
                feed(path, r.status_code, "directory", acc)

        async def probe_file(path):
            nonlocal checked_files
            if halted():
                return
            url = root + path
            async with sem:
                try:
                    r = await c.get(url)
                except Exception:  # noqa: BLE001
                    feed(path, "ERR", "file", False)
                    return
                checked_files += 1
                if r.status_code >= 400:
                    feed(path, r.status_code, "file", False)
                    return
                name = path.rsplit("/", 1)[-1]
                group, sev = fsaudit.file_type(name)
                body = r.text[:400] if r.headers.get("content-type", "").startswith(("text", "application")) else ""
                acc = False
                if group.startswith("Source Code"):
                    if name.lower() not in ENTRY_SCRIPTS and (PHP_SOURCE_RE.search(body) or re.search(r"<\?php|<\?=", body)):
                        acc = True
                        record({"url": url, "path": path, "status": r.status_code, "kind": "file", "listing": False,
                                "group": "Source Code Disclosure", "ftype": group, "severity": "critical",
                                "reason": "Server returned raw source code instead of executing it - full logic and any embedded credentials are readable.",
                                "secret": bool(SECRET_RE.search(body))})
                    feed(path, r.status_code, "file", acc)
                    return   # normal executed server script - fine
                if sev is None:
                    asset_counts[group] = asset_counts.get(group, 0) + 1   # expected public asset - count only
                    feed(path, r.status_code, "file", True)
                    return
                record({"url": url, "path": path, "status": r.status_code, "kind": "file", "listing": False,
                        "group": group, "ftype": group, "severity": "critical" if SECRET_RE.search(body) else sev,
                        "reason": f"A {group.lower()} file is directly downloadable over the web.",
                        "secret": bool(SECRET_RE.search(body))})
                feed(path, r.status_code, "file", True)

        await asyncio.gather(*( [probe_dir(d) for d in dirs] + [probe_file(f) for f in files] ))

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    accessible.sort(key=lambda x: (sev_order.get(x["severity"], 5), x["group"], x["path"]))
    return {"checked_files": checked_files, "checked_dirs": checked_dirs,
            "accessible": accessible, "asset_counts": asset_counts, "scanned": scanned}


HREF_IN_LISTING = re.compile(r'<a[^>]+href=["\']([^"\'?#]+)["\']', re.I)


async def crawl_listings(origin: str, start_bases: list[str], emit=lambda e: None, halted=lambda: False,
                         max_items: int = 5000, max_depth: int = 10) -> dict:
    """Live directory-listing crawler (no local folder needed): starting from the app's web/ and project
    bases, fetch each folder; where the server has directory indexing enabled, parse the listing, recurse
    into every subfolder, and record every file found - a real walk of the deployed directory tree."""
    o = origin.rstrip("/")
    accessible: list[dict] = []
    asset_counts: dict[str, int] = {}
    seen: set[str] = set()
    checked_dirs = checked_files = 0
    async with httpx.AsyncClient(verify=False, timeout=6, follow_redirects=True,
                                 headers={"User-Agent": "StressScope/1.0 (authorised directory scan)"}) as c:
        sem = asyncio.Semaphore(30)

        async def fetch(path):
            async with sem:
                try:
                    return await c.get(o + path)
                except Exception:  # noqa: BLE001
                    return None

        # BFS over directories that return a listing
        frontier = [(b if b.startswith("/") else "/" + b, 0) for b in dict.fromkeys(start_bases)]
        while frontier and len(accessible) < max_items and not halted():
            batch, frontier = frontier[:40], frontier[40:]
            results = await asyncio.gather(*(fetch(p) for p, _ in batch))
            next_frontier = []
            for (path, depth), r in zip(batch, results):
                if r is None or r.status_code >= 400:
                    continue
                checked_dirs += 1
                body = r.text[:200000]
                if not DIR_LISTING_RE.search(body):
                    continue
                sensitive = bool(DIR_SENSITIVE_RE.search(path))
                key = o + path
                if key not in seen:
                    seen.add(key)
                    accessible.append({"url": key, "path": path.lstrip("/"), "status": 200, "kind": "directory",
                                       "listing": True, "group": "Directory Listing", "ftype": "directory",
                                       "severity": "critical" if sensitive else "high",
                                       "reason": "Directory listing is enabled - every file in this folder can be browsed and downloaded."})
                    emit({"type": "exposure_hit", "finding": accessible[-1]})
                for href in set(HREF_IN_LISTING.findall(body)):
                    if href in ("../", "./", "/") or href.startswith(("?", "#", "http://", "https://", "mailto:")):
                        continue
                    child = path + ("" if path.endswith("/") else "/") + href.lstrip("/")
                    curl = o + child
                    if curl in seen:
                        continue
                    if href.endswith("/"):          # subdirectory -> recurse
                        if depth < max_depth:
                            next_frontier.append((child, depth + 1))
                    else:                           # file -> record
                        seen.add(curl)
                        checked_files += 1
                        name = href.rsplit("/", 1)[-1]
                        if name.lower() in ENTRY_SCRIPTS:   # ignore index.php / entry scripts
                            continue
                        group, sev = fsaudit.file_type(name)
                        if sev is None:
                            asset_counts[group] = asset_counts.get(group, 0) + 1
                            continue
                        item = {"url": curl, "path": child.lstrip("/"), "status": 200, "kind": "file",
                                "listing": False, "group": group, "ftype": group, "severity": sev,
                                "reason": f"A {group.lower()} file is directly downloadable (found via an open directory listing)."}
                        if group.startswith("Source Code"):
                            # a server script usually executes - only flag it if raw source actually leaks
                            fr = await fetch(child)
                            if not (fr and fr.status_code < 400 and (PHP_SOURCE_RE.search(fr.text[:400]) or re.search(r"<\?php|<\?=", fr.text[:400]))):
                                continue
                            item.update(group="Source Code Disclosure", severity="critical",
                                        reason="Server returned raw source instead of executing it (found via an open directory listing).")
                        accessible.append(item)
                        emit({"type": "exposure_hit", "finding": item})
                        if len(accessible) >= max_items:
                            break
            frontier = next_frontier + frontier
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    accessible.sort(key=lambda x: (sev_order.get(x["severity"], 5), x["group"], x["path"]))
    return {"checked_files": checked_files, "checked_dirs": checked_dirs,
            "accessible": accessible, "asset_counts": asset_counts}
