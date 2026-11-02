"""Categorisation, scoring and rule-based "intelligence" for the final report."""
from __future__ import annotations

import re
import statistics
from collections import Counter, defaultdict
from urllib.parse import parse_qsl, urlparse

AUTH_WORDS = ("login", "logout", "signin", "sign-in", "signup", "sign-up", "register", "forgot",
              "reset", "password", "auth", "sso", "verify", "2fa", "otp")
ROUTE_KEYS = ("page", "p", "route", "r", "module", "mod", "action", "view", "controller", "c", "section", "do")
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEC_HEADERS = {
    "hsts": ("Strict-Transport-Security", "Forces HTTPS for future visits"),
    "csp": ("Content-Security-Policy", "Mitigates XSS and data injection"),
    "xfo": ("X-Frame-Options", "Prevents clickjacking"),
    "xcto": ("X-Content-Type-Options", "Stops MIME sniffing"),
    "refpol": ("Referrer-Policy", "Limits referrer leakage"),
}


def _title(s: str) -> str:
    s = re.sub(r"[-_+.]+", " ", s).strip()
    return s.upper() if s.lower() in ("api", "faq", "cms", "crm", "erp", "seo", "ui", "ux") else s.title() or "Home"


def category_for(url: str, is_login: bool = False) -> str:
    if is_login:
        return "Authentication"
    p = urlparse(url)
    segs = [s for s in p.path.split("/") if s]
    q = dict(parse_qsl(p.query))
    if p.fragment.startswith(("/", "!/")):
        frag = p.fragment.lstrip("!").split("?")[0]
        segs = [s for s in frag.split("/") if s]
    segs = [re.sub(r"\.(php|html?|aspx?|jsp)$", "", s, flags=re.I) for s in segs]
    if len(segs) > 1 and re.fullmatch(r"[a-z]{2}([-_][a-z]{2})?", segs[0], re.I):
        segs = segs[1:]
    # front-controller pattern: .../index.php?r=controller/action (Yii1/Yii2), or ?page=/?route=/?view= style
    # routing - the LAST path segment is the entry script, however deep it sits (e.g. /app/web/index.php),
    # so the real "screen" lives in the query string, not the path.
    if segs and segs[-1].lower() in ("index", "default", "main"):
        for k in ROUTE_KEYS:
            route = q.get(k)
            if route:
                return _title(route.split("/")[0])
        segs = segs[:-1]
        if segs and segs[-1].lower() in ("web", "public", "www", "htdocs", "html"):
            segs = segs[:-1]
        if not segs:
            return "Home"
        first = segs[-1].lower()
        if any(first == w or first.startswith(w) for w in AUTH_WORDS):
            return "Authentication"
        return _title(segs[-1])
    if not segs:
        for k in ROUTE_KEYS:
            if q.get(k):
                return _title(q[k].split("/")[0])
        return "Home"
    first = segs[0].lower()
    if any(first == w or first.startswith(w) for w in AUTH_WORDS):
        return "Authentication"
    if re.fullmatch(r"\d+|[0-9a-f-]{16,}", first):
        return "Other"
    return _title(segs[0])


def pct(vals, p):
    if not vals:
        return 0.0
    s = sorted(vals)
    k = (len(s) - 1) * p / 100
    f, c = int(k), min(int(k) + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


def avg(vals):
    vals = [v for v in vals if v is not None]
    return round(sum(vals) / len(vals), 1) if vals else 0.0


def _tested(pages):
    return [p for p in pages if p.get("state") == "done" and not p.get("alias_of") and p.get("status")]


def grade(score):
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 55 else "F"


DSCAN_GROUP_ORDER = ["Directory Listing", "Source Code Disclosure", "Database", "Key / Certificate", "Config",
                     "Archive", "Backup / Temp", "Executable", "Log", "Source Map", "Data Export", "Data / Text",
                     "Document", "Other", "Protected Directory"]


FIX_SUGGEST = {
    "Directory Listing": "Turn off directory indexing (Apache: Options -Indexes; nginx: autoindex off) and drop an empty index.html into the folder.",
    "Source Code Disclosure": "Fix the web-server handler so these extensions execute; never serve them as plain text.",
    "Database": "Move database files/dumps outside the web root and block the path at the server.",
    "database_dump": "Move database files/dumps outside the web root; never keep real dumps in a web-served folder.",
    "Key / Certificate": "Move keys/certs outside the web root immediately and rotate anything that was exposed.",
    "credential_key": "Move keys/.env/credentials outside the web root and rotate any exposed secret.",
    "Config": "Move config out of the web root or deny direct access; keep secrets in environment variables.",
    "sensitive_config": "Move config out of the web root or deny direct access to it.",
    "Archive": "Delete archives/backups from the web root - they often contain full source or data.",
    "archive": "Delete archives/backups from the web root.",
    "Backup / Temp": "Remove backup/temp/editor-swap files from the deployed folder.",
    "backup": "Remove backup/temp files from the deployed folder.",
    "Executable": "Remove executables from the web root; they should never be downloadable.",
    "executable": "Remove executables from the web root.",
    "Log": "Move logs outside the web root; they leak paths, queries and stack traces.",
    "log": "Move logs outside the web root.",
    "Source Map": "Do not deploy .map files to production - they reveal original source.",
    "exposed_repo": "Block or remove the .git/.svn folder from the web root - the whole source history is downloadable.",
    "debug_script": "Delete leftover debug/diagnostic scripts (phpinfo, test.php, etc.).",
}


def _fix_for(cat: str) -> str:
    return FIX_SUGGEST.get(cat, "Move this file outside the public web root or block direct access to it at the web server.")


def _build_dir_tree(items: list[dict], all_dirs: list[str] | None = None) -> dict:
    """Nested folder tree. `all_dirs` seeds EVERY project folder (so the whole structure shows, even clean
    ones); `items` are the issues overlaid on top, and folders carry the worst severity found beneath them."""
    root = {"name": "/", "path": "", "children": {}, "issues": [], "severity": None, "count": 0}

    def ensure(parts):
        node = root
        for i, part in enumerate(parts):
            node = node["children"].setdefault(part, {"name": part, "path": "/".join(parts[: i + 1]),
                                                      "children": {}, "issues": [], "severity": None, "count": 0})
        return node

    for d in (all_dirs or [])[:4000]:
        rel = d.strip("/")
        if rel:
            ensure(rel.split("/"))

    def worse(a, b):
        if a is None:
            return b
        if b is None:
            return a
        return a if SEV_ORDER.get(a, 9) <= SEV_ORDER.get(b, 9) else b

    for it in items:
        rel = (it.get("rel_root") or "").strip("/")
        if not rel:
            continue
        parts = rel.split("/")
        is_dir = it.get("is_dir") or rel.endswith("/")
        node = root
        node["count"] += 1
        node["severity"] = worse(node["severity"], it["severity"])
        for i, part in enumerate(parts):
            leaf = (i == len(parts) - 1)
            if leaf and not is_dir:
                node["issues"].append(it)
            else:
                ch = node["children"].setdefault(part, {"name": part, "path": "/".join(parts[: i + 1]), "children": {}, "issues": [], "severity": None, "count": 0})
                ch["count"] += 1
                ch["severity"] = worse(ch["severity"], it["severity"])
                if leaf and is_dir:
                    ch["issues"].append(it)
                node = ch

    def finalize(node):
        node["children"] = [finalize(c) for c in sorted(node["children"].values(), key=lambda c: (SEV_ORDER.get(c["severity"], 9), c["name"]))]
        return node
    return finalize(root)


def _assemble_tree(fs_result, local_findings, dscan) -> dict:
    """Combine on-disk risky files and HTTP-reachable items into one project-root-relative issue tree."""
    import os as _os
    web_prefix = ""
    if fs_result and fs_result.get("ok") and fs_result.get("web_root"):
        try:
            web_prefix = _os.path.relpath(fs_result["web_root"], fs_result["root"]).replace("\\", "/")
            if web_prefix == ".":
                web_prefix = ""
        except Exception:  # noqa: BLE001
            web_prefix = ""
    by_path: dict[str, dict] = {}
    for f in local_findings:
        rel = f["rel_root"]
        by_path[rel] = {"rel_root": rel, "severity": f["severity"], "category": f["category"],
                        "reason": f"{f['category'].replace('_',' ')} file on disk" + (" inside the public web root" if f["in_web_root"] else ""),
                        "fix": _fix_for(f["category"]), "accessible": False, "url": "", "is_dir": f.get("is_dir", False)}
    for a in dscan.get("accessible", []):
        # directory-scan paths are already project-root-relative (probed at the project base), so use as-is
        rel = a["path"].strip("/")
        existing = by_path.get(rel)
        if existing:
            existing.update(accessible=True, url=a["url"], reason=a["reason"])
            existing["severity"] = min(existing["severity"], a["severity"], key=lambda s: SEV_ORDER.get(s, 9))
        else:
            by_path[rel] = {"rel_root": rel, "severity": a["severity"], "category": a.get("group", "Other"),
                            "reason": a["reason"], "fix": _fix_for(a.get("group", "")), "accessible": True,
                            "url": a["url"], "is_dir": a.get("kind") == "directory"}
    all_dirs = (fs_result.get("all_dirs") if fs_result and fs_result.get("ok") else None)
    return _build_dir_tree(list(by_path.values()), all_dirs)


def _dscan_report(dscan: dict) -> dict:
    """Shape the raw directory sweep into grouped sections for the report UI/exports."""
    acc = dscan.get("accessible", [])
    groups = defaultdict(list)
    for a in acc:
        groups[a["group"]].append(a)
    ordered = []
    for g in DSCAN_GROUP_ORDER + [k for k in groups if k not in DSCAN_GROUP_ORDER]:
        if groups.get(g):
            items = sorted(groups[g], key=lambda x: (SEV_ORDER.get(x["severity"], 5), x["path"]))
            ordered.append({"group": g, "count": len(items),
                            "severity": min((i["severity"] for i in items), key=lambda s: SEV_ORDER.get(s, 5)),
                            "items": items})
    return {
        "checked_files": dscan.get("checked_files", 0), "checked_dirs": dscan.get("checked_dirs", 0),
        "accessible_total": len(acc), "groups": ordered, "asset_counts": dscan.get("asset_counts", {}),
        "scanned": dscan.get("scanned", []),
        "all_items": dscan.get("all_items", []),
    }


def build_forms(pages):
    out = []
    for p in pages:
        for ft in p.get("form_tests") or []:
            out.append({"page": p["url"], "category": p["category"], **ft})
    return out


def build_uploads(forms):
    out = []
    for f in forms:
        for u in f.get("upload") or []:
            out.append({"page": f["page"], "category": f.get("category"), "form_action": f.get("form_action"), **u})
    return out


def build_report(meta: dict, pages: list[dict], stress: dict | None, extras: dict) -> dict:
    tested = _tested(pages)
    ok_pages = [p for p in tested if p["status"] < 400]
    by_url = {p["url"]: p for p in pages}
    # ---------------------------------------------------------------- categories
    cats: dict[str, list] = defaultdict(list)
    for p in pages:
        cats[p["category"]].append(p)
    load_by_url = (stress or {}).get("per_page", {})
    site_avg_load = avg([p["load"] for p in ok_pages if p.get("load")]) or 1
    categories = []
    for name, ps in cats.items():
        t = [p for p in ps if p in tested]
        bad = [p for p in t if p["status"] >= 400]
        cerr = sum(len(p.get("console_errors", [])) + len(p.get("page_errors", [])) for p in t)
        loads = [p["load"] for p in t if p.get("load")]
        p95s = [load_by_url[p["url"].split("#")[0]]["p95"] for p in ps if p["url"].split("#")[0] in load_by_url]
        status = "Healthy"
        if bad or any(p.get("state") == "error" for p in ps):
            status = "Critical"
        elif cerr or (loads and avg(loads) > 2500):
            status = "Warning"
        categories.append({
            "name": name, "pages": len(ps), "tested": len(t),
            "restricted": sum(1 for p in ps if p.get("state") == "restricted"),
            "errors": len(bad) + sum(1 for p in ps if p.get("state") == "error"),
            "console_errors": cerr,
            "avg_load": avg(loads), "max_load": round(max(loads), 1) if loads else 0,
            "avg_size_kb": avg([p.get("size_kb") for p in t]),
            "avg_requests": avg([p.get("requests") for p in t]),
            "load_p95": avg(p95s), "status": status,
            "urls": [p["url"] for p in ps],
        })
    categories.sort(key=lambda c: (-c["pages"], c["name"]))

    # ---------------------------------------------------------------- broken links
    broken = []
    for p in pages:
        for child in p.get("children", []):
            c = by_url.get(child)
            if c and (c.get("state") == "error" or (c.get("status") or 0) >= 400):
                broken.append({"source": p["url"], "target": child, "status": c.get("status") or c.get("error") or "error",
                               "text": (p.get("child_text", {}) or {}).get(child, "")})
    for ext in extras.get("external", []):
        if ext["broken"]:
            for src in ext["sources"][:3]:
                broken.append({"source": src, "target": ext["url"], "status": ext["status"], "text": "external"})

    # ---------------------------------------------------------------- insights
    ins: list[dict] = []

    def add(sev, area, title, detail, fix, urls=None):
        urls = list(dict.fromkeys(urls or []))
        ins.append({"severity": sev, "area": area, "title": title, "detail": detail, "fix": fix,
                    "count": len(urls), "pages": urls[:40]})

    def u(ps):
        return [p["url"] for p in ps]

    s5 = [p for p in tested if p["status"] >= 500]
    if s5:
        add("critical", "Reliability", f"{len(s5)} page(s) returned a server error (5xx)",
            "Server-side failures were returned when the page was requested.",
            "Check application/server logs for the listed URLs; fix the unhandled exception or upstream failure.", u(s5))
    s4 = [p for p in tested if 400 <= p["status"] < 500 and p["status"] not in (401, 403)]
    if s4:
        add("high", "Reliability", f"{len(s4)} internal link(s) lead to client errors (4xx)",
            "Pages linked from the site respond with 404/410/400. Visitors will see error screens.",
            "Fix or remove the links, or restore/redirect the missing pages (301).", u(s4))
    forb = [p for p in tested if p["status"] in (401, 403)]
    if forb:
        add("medium", "Access", f"{len(forb)} page(s) denied access (401/403)",
            "These pages refused the crawler even after authentication (or no credentials were supplied).",
            "Confirm this is intentional, or test again with an account that has the required role.", u(forb))
    errs = [p for p in pages if p.get("state") == "error"]
    if errs:
        add("high", "Reliability", f"{len(errs)} page(s) failed to load (timeout / network error)",
            "; ".join(sorted({(p.get('error') or '')[:90] for p in errs})[:4]),
            "Investigate timeouts, DNS or TLS problems and server capacity for these URLs.", u(errs))
    restricted = [p for p in pages if p.get("state") == "restricted"]
    if restricted:
        add("info", "Coverage", f"{len(restricted)} page(s) need a login and were not tested",
            "Credentials were skipped or rejected, so protected screens were only detected, not exercised.",
            "Run the scan again and supply valid credentials to cover the protected area.", u(restricted))

    slow_hi = [p for p in ok_pages if (p.get("load") or 0) > 4000]
    slow_mid = [p for p in ok_pages if 2500 < (p.get("load") or 0) <= 4000]
    if slow_hi:
        add("high", "Performance", f"{len(slow_hi)} page(s) take longer than 4 seconds to load",
            f"Slowest: {max(slow_hi, key=lambda p: p['load'])['url']} ({max(p['load'] for p in slow_hi):.0f} ms).",
            "Profile the slowest requests, enable caching/CDN, compress and defer heavy assets, optimise DB queries.", u(slow_hi))
    if slow_mid:
        add("medium", "Performance", f"{len(slow_mid)} page(s) take 2.5-4 seconds to load",
            "Load time is above the recommended 2.5 s threshold.", "Optimise images, bundle/minify scripts and add caching.", u(slow_mid))
    slow_ttfb = [p for p in ok_pages if (p.get("ttfb") or 0) > 800]
    if slow_ttfb:
        add("medium", "Performance", f"{len(slow_ttfb)} page(s) have slow server response (TTFB > 800 ms)",
            "The server takes long to start answering, usually a backend/database bottleneck.",
            "Add server-side caching, optimise queries, and review application start-up/auth middleware cost.", u(slow_ttfb))
    lcp = [p for p in ok_pages if (p.get("lcp") or 0) > 2500]
    if lcp:
        add("high" if any(p["lcp"] > 4000 for p in lcp) else "medium", "Performance",
            f"{len(lcp)} page(s) have poor Largest Contentful Paint (> 2.5 s)",
            "The main visible content renders late, hurting perceived speed and Core Web Vitals.",
            "Preload hero images/fonts, serve responsive images, reduce render-blocking CSS/JS.", u(lcp))
    cls = [p for p in ok_pages if (p.get("cls") or 0) > 0.1]
    if cls:
        add("medium", "Performance", f"{len(cls)} page(s) have layout shift above 0.1 (CLS)",
            "Content jumps while loading.", "Reserve space (width/height) for images, ads, embeds and dynamic widgets.", u(cls))
    heavy = [p for p in ok_pages if (p.get("size_kb") or 0) > 3072]
    if heavy:
        add("medium", "Performance", f"{len(heavy)} page(s) transfer more than 3 MB",
            "Large payloads slow mobile users and raise bandwidth under load.", "Compress images (WebP/AVIF), lazy-load, split bundles.", u(heavy))
    many = [p for p in ok_pages if (p.get("requests") or 0) > 100]
    if many:
        add("low", "Performance", f"{len(many)} page(s) issue more than 100 requests",
            "Excess requests increase latency and server load.", "Bundle assets, use HTTP/2 multiplexing, sprite icons, remove unused third-party tags.", u(many))
    nocomp = [p for p in ok_pages if not p.get("compressed") and (p.get("html_kb") or 0) > 10]
    if nocomp:
        add("medium", "Performance", f"{len(nocomp)} HTML document(s) are served without compression",
            "gzip/brotli would cut HTML transfer by 70-80%.", "Enable gzip or brotli on the web server (e.g. Apache mod_deflate).", u(nocomp))
    dom = [p for p in ok_pages if (p.get("dom_nodes") or 0) > 3000]
    if dom:
        add("low", "Performance", f"{len(dom)} page(s) have very large DOMs (> 3000 nodes)",
            "Big DOMs slow rendering and scripting.", "Paginate or virtualise long lists.", u(dom))

    jse = [p for p in tested if p.get("console_errors") or p.get("page_errors")]
    if jse:
        n = sum(len(p.get("console_errors", [])) + len(p.get("page_errors", [])) for p in jse)
        sample = (jse[0].get("page_errors") or jse[0].get("console_errors"))[0][:140]
        add("high" if len(jse) > 5 else "medium", "Functionality", f"{n} JavaScript/console error(s) on {len(jse)} page(s)",
            f"Example: {sample}", "Open DevTools on the listed pages and fix the failing scripts - these often break interactive features.", u(jse))
    failed = [p for p in tested if p.get("failed_requests")]
    if failed:
        n = sum(len(p["failed_requests"]) for p in failed)
        f0 = failed[0]["failed_requests"][0]
        add("medium", "Functionality", f"{n} sub-resource request(s) failed on {len(failed)} page(s)",
            f"Example: {f0.get('url', '')[:110]} -> {f0.get('status')}", "Fix missing files / CORS / blocked third-party calls.", u(failed))
    bimg = [p for p in tested if p.get("broken_images")]
    if bimg:
        add("medium", "Functionality", f"Broken images on {len(bimg)} page(s)", f"{sum(p['broken_images'] for p in bimg)} image(s) failed to render.",
            "Restore the image files or fix their paths.", u(bimg))
    if broken:
        add("high", "Reliability", f"{len(broken)} broken link occurrence(s) detected", "See the Broken Links sheet for source -> target pairs.",
            "Update the anchors on the source pages.", [b["source"] for b in broken])

    # security
    https = urlparse(meta["url"]).scheme == "https"
    local = urlparse(meta["url"]).hostname in ("localhost", "127.0.0.1", "::1") or (urlparse(meta["url"]).hostname or "").endswith((".localhost", ".test"))
    if not https:
        add("info" if local else "high", "Security", "Site is served over plain HTTP",
            "Traffic (including logins) can be read or modified in transit." + (" (Local development host.)" if local else ""),
            "Install a TLS certificate and redirect HTTP to HTTPS.")
    doc_pages = ok_pages
    if doc_pages:
        for key, (hdr, why) in SEC_HEADERS.items():
            if key == "hsts" and not https:
                continue
            miss = [p for p in doc_pages if not p.get("sec_headers", {}).get(key)]
            if miss and len(miss) >= max(1, len(doc_pages) * 0.5):
                add("medium" if key in ("csp", "hsts", "xfo") else "low", "Security", f"Missing {hdr} header ({len(miss)}/{len(doc_pages)} pages)",
                    why + ".", f"Add the {hdr} response header at the web server or application level.", u(miss))
    disc = [p for p in doc_pages if p.get("sec_headers", {}).get("server_disclosure")]
    if disc:
        add("low", "Security", "Server technology/version is disclosed in headers", f"Example: {disc[0]['sec_headers']['server_disclosure']}",
            "Remove or genericise Server / X-Powered-By headers.", u(disc))
    mixed = [p for p in tested if p.get("mixed_content")]
    if mixed:
        add("high", "Security", f"Mixed content (HTTP resources on HTTPS) on {len(mixed)} page(s)", "Browsers block or warn on these requests.",
            "Load every asset over HTTPS.", u(mixed))
    for ck in extras.get("cookie_issues", []):
        add("medium", "Security", f"Cookie '{ck['name']}' lacks: {', '.join(ck['missing'])}", "Weak cookie flags make session theft or CSRF easier.",
            "Set Secure, HttpOnly and SameSite attributes on session cookies.")

    # seo + a11y
    def group(cond, sev, area, title, detail, fix):
        ps = [p for p in ok_pages if cond(p)]
        if ps:
            add(sev, area, f"{title} ({len(ps)} page(s))", detail, fix, u(ps))
    group(lambda p: not p.get("title"), "medium", "SEO", "Missing <title>", "Search engines and browser tabs have no title.", "Add a unique <title> per page.")
    group(lambda p: not p.get("meta_description"), "low", "SEO", "Missing meta description", "Snippets in search results are auto-generated.", "Add a 120-160 char meta description.")
    group(lambda p: p.get("h1_count", 1) == 0, "low", "SEO", "No <h1> heading", "Pages should have one main heading.", "Add a single descriptive <h1>.")
    group(lambda p: p.get("h1_count", 1) > 1, "low", "SEO", "Multiple <h1> headings", "Ambiguous main topic.", "Keep a single <h1>.")
    group(lambda p: not p.get("viewport"), "medium", "SEO", "Missing viewport meta tag", "Page will not scale correctly on mobile.", 'Add <meta name="viewport" content="width=device-width, initial-scale=1">.')
    group(lambda p: not p.get("lang"), "low", "Accessibility", "Missing lang attribute on <html>", "Screen readers can't pick the right voice.", "Add lang=\"en\" (or proper code).")
    group(lambda p: p.get("img_no_alt", 0) > 0, "medium", "Accessibility", "Images without alt text", "Screen reader users miss image content.", "Add meaningful alt attributes (empty alt for decorative images).")
    group(lambda p: p.get("buttons_no_name", 0) > 0, "medium", "Accessibility", "Buttons/links without accessible names", "Icon-only controls are unannounced.", "Add aria-label or visible text.")
    group(lambda p: p.get("inputs_no_label", 0) > 0, "medium", "Accessibility", "Form fields without labels", "Inputs lack <label>/aria-label.", "Associate a <label for> with every field.")
    group(lambda p: p.get("mobile_overflow"), "medium", "Responsive", "Horizontal overflow on mobile (390 px)", "Content is wider than a phone screen.", "Fix fixed-width elements; use responsive CSS.")
    titles = Counter(p.get("title") for p in ok_pages if p.get("title"))
    dup = [p for p in ok_pages if p.get("title") and titles[p["title"]] > 1]
    if dup and len(dup) > 1:
        add("low", "SEO", f"Duplicate page titles ({len(dup)} pages)", "Pages share identical titles.", "Give each page a unique title.", u(dup))

    ext_broken = [e for e in extras.get("external", []) if e["broken"]]
    if ext_broken:
        add("medium", "Reliability", f"{len(ext_broken)} broken external link(s)", "; ".join(f"{e['url'][:60]} ({e['status']})" for e in ext_broken[:3]),
            "Update or remove the dead external links.", [s for e in ext_broken for s in e["sources"]])

    # category hotspots
    for c in categories:
        if c["avg_load"] and site_avg_load and c["avg_load"] > site_avg_load * 1.6 and c["tested"] >= 2 and c["avg_load"] > 1500:
            add("low", "Performance", f"'{c['name']}' section is {c['avg_load'] / site_avg_load:.1f}x slower than the site average",
                f"Average {c['avg_load']:.0f} ms vs site {site_avg_load:.0f} ms.", "Focus optimisation effort on this section first.", c["urls"])

    if extras.get("crawl_limited"):
        add("info", "Coverage", "Crawl stopped at the page limit", f"More pages exist than the configured limit ({meta['max_pages']}).",
            "Raise 'Max pages' to cover the remainder.")

    # ---------------------------------------------------------------- forms
    forms = build_forms(pages)
    uploads = build_uploads(forms)
    form_errors = [f for f in forms if "error" in f and "cases" not in f]
    testable_forms = [f for f in forms if "cases" in f]
    no_client_validation = [f for f in testable_forms if any(c["case"] == "Empty required fields" and not c["pass"] for c in f["cases"])]
    if no_client_validation:
        add("medium", "Forms", f"{len(no_client_validation)} form(s) have no client-side validation on required fields",
            "Required fields could be submitted empty; the server must be relied on entirely to reject bad input.",
            "Add the required attribute (and matching server-side checks) to mandatory fields.",
            [f["page"] for f in no_client_validation])
    no_format_validation = [f for f in testable_forms if any("Invalid format" in c["case"] and not c["pass"] for c in f["cases"])]
    if no_format_validation:
        add("low", "Forms", f"{len(no_format_validation)} form(s) accepted an invalid-format value without client-side pushback",
            "e.g. a malformed email/number/pattern value was not caught in the browser.",
            "Add pattern/type constraints client-side; confirm the server rejects malformed input too.",
            [f["page"] for f in no_format_validation])
    sensitive_skipped = sum(len(f.get("skipped_sensitive") or []) for f in forms)
    if sensitive_skipped:
        add("info", "Forms", f"{sensitive_skipped} sensitive-looking field(s) were skipped automatically",
            "Payment/ID-style fields (card number, CVV, SSN, bank details) are never auto-filled by the scanner.",
            "Test these fields manually with your own authorised test data.")
    if form_errors:
        add("low", "Forms", f"{len(form_errors)} form(s) could not be tested automatically",
            "; ".join(sorted({(e.get('error') or '')[:90] for e in form_errors})[:3]),
            "Review these forms manually.", [e["page"] for e in form_errors])

    # ---------------------------------------------------------------- upload security
    def up(cases):
        return [u for u in uploads if u["case"] in cases]

    rce = [u for u in uploads if u.get("executed") is True]
    if rce:
        add("critical", "Upload Security", f"{len(rce)} file upload accepted and EXECUTED a disguised script",
            "A non-image file (PHP/SVG with embedded content) was uploaded and the server ran it when visited - this is remote code execution via file upload.",
            "Validate uploads by real content/MIME sniffing (not extension), store uploads outside the web root or with execution disabled, and re-encode/strip images.",
            [u["page"] for u in rce])
    disguised_accepted = [u for u in up(("double_extension", "executable_extension", "svg_script")) if u["status"] == "accepted" and u.get("executed") is not True]
    if disguised_accepted:
        add("high", "Upload Security", f"{len(disguised_accepted)} disguised/executable file upload was accepted",
            "A script file disguised as an image (double extension, executable extension, or SVG with markup) was accepted by the upload form.",
            "Whitelist allowed MIME types by content inspection, rename stored files, and block script extensions outright.",
            [u["page"] for u in disguised_accepted])
    mismatch_accepted = [u for u in up(("mismatched_content",)) if u["status"] == "accepted"]
    if mismatch_accepted:
        add("medium", "Upload Security", f"{len(mismatch_accepted)} upload accepted content that doesn't match its claimed type",
            "A file whose real content differs from its extension/MIME type was accepted.",
            "Validate file content (magic bytes), not just the extension or client-supplied MIME type.", [u["page"] for u in mismatch_accepted])
    renderable = [u for u in up(("svg_script", "mismatched_content")) if u.get("content_type_risk")]
    if renderable:
        add("high", "Upload Security", f"{len(renderable)} uploaded file is served with a content-type a browser would render as active markup",
            "An SVG or HTML-disguised-as-image upload is stored and later served in a way that a browser could execute its embedded markup/script when opened directly - a stored XSS risk, distinct from server-side code execution.",
            "Force a download disposition (Content-Disposition: attachment) and a safe Content-Type for user uploads, or sanitise/strip SVG and HTML content on upload.",
            [u["page"] for u in renderable])
    oversized_accepted = [u for u in up(("oversized",)) if u["status"] == "accepted"]
    if oversized_accepted:
        add("medium", "Upload Security", f"{len(oversized_accepted)} upload form has no file size limit",
            "A 6 MB test file was accepted without rejection.", "Enforce a server-side maximum upload size.", [u["page"] for u in oversized_accepted])
    traversal_accepted = [u for u in up(("path_traversal_name",)) if u["status"] == "accepted"]
    if traversal_accepted:
        add("high", "Upload Security", f"{len(traversal_accepted)} upload form did not sanitise a path-traversal filename",
            "A filename containing '../' sequences was accepted as-is.", "Sanitise/regenerate filenames server-side; never use the client-supplied name directly.",
            [u["page"] for u in traversal_accepted])
    empty_accepted = [u for u in up(("empty",)) if u["status"] == "accepted"]
    if empty_accepted:
        add("low", "Upload Security", f"{len(empty_accepted)} upload form accepted a 0-byte file", "Empty uploads were not rejected.",
            "Reject zero-byte uploads server-side.", [u["page"] for u in empty_accepted])

    # ---------------------------------------------------------------- exposure scan (unauthenticated)
    exposure_findings = extras.get("exposure") or []
    for sev in ("critical", "high", "medium", "low"):
        items = [e for e in exposure_findings if e["severity"] == sev]
        if items:
            add(sev, "Exposure", f"{len(items)} sensitive path(s) are publicly accessible without logging in" if sev in ("critical", "high")
                else f"{len(items)} path(s) of lower sensitivity are publicly accessible",
                "; ".join(f"{e['path']} ({e['status']}{', secret pattern found' if e['contains_secret_pattern'] else ''}{', directory listing' if e['directory_listing'] else ''})" for e in items[:5]),
                "Block these paths at the web server (deny-list or move outside the web root) and confirm no credentials/source code are exposed.",
                [e["url"] for e in items])

    # ---------------------------------------------------------------- base URL scope
    out_of_base = extras.get("out_of_base") or []
    if extras.get("base_url") and out_of_base:
        samples = sorted({c["url"] for c in out_of_base})[:10]
        add("medium" if len(out_of_base) > 5 else "info", "Scope",
            f"{len(out_of_base)} request(s) were made outside the configured base URL ({extras['base_url']})",
            "These GET/POST calls landed on a path that does not start with the base URL you set - this can indicate another app sharing the host, a misconfigured route, or an entry point outside the intended folder.",
            "Review each listed call: confirm it is expected, or restrict routing/web-server rules to the intended base path.", samples)

    # ---------------------------------------------------------------- local filesystem audit (project folder)
    fs_result = extras.get("fs_result")
    local_findings = (fs_result or {}).get("findings", []) if fs_result and fs_result.get("ok") else []
    if fs_result and not fs_result.get("ok"):
        add("info", "Directory", "Local project folder could not be scanned", fs_result.get("error", ""), "Check the folder path and try again.")
    elif local_findings:
        for sev in ("critical", "high", "medium", "low"):
            items = [f for f in local_findings if f["severity"] == sev]
            if items:
                where = sum(1 for f in items if f["in_web_root"])
                add(sev, "Directory", f"{len(items)} {sev}-risk file(s) found on disk in the project folder" + (f" - {where} inside the public web root" if where else ""),
                    "; ".join(f"{f['rel_root']} ({f['category']})" for f in items[:5]),
                    "Remove files that don't belong in a deployed application - archives, backups, DB dumps and keys should never sit inside the web-served folder.",
                    [f["rel_root"] for f in items])

    # ---- SQL-injection (error-based, read-only probe)
    sql_findings = extras.get("sql_findings") or []
    if sql_findings:
        add("critical", "Injection", f"{len(sql_findings)} parameter(s) show possible SQL injection (database error leak)",
            "A single-quote probe caused a database error to surface, which means user input reaches a SQL query unsanitised. Example: "
            + "; ".join(f"{s['param']} on {s['path']}" for s in sql_findings[:5]),
            "Use parameterised queries / prepared statements (bind every value), never string-concatenate input into SQL. In Yii use ActiveRecord or bound params, and turn off detailed DB errors in production.",
            [s["url"] for s in sql_findings])

    # ---- directory scan: directly-accessible folders & files, grouped by category
    dscan = extras.get("directory_scan") or {}
    dgroups: dict[str, list] = defaultdict(list)
    for a in dscan.get("accessible", []):
        dgroups[a["group"]].append(a)
    listings = dgroups.get("Directory Listing", [])
    if listings:
        add("high" if not any(l["severity"] == "critical" for l in listings) else "critical", "Directory",
            f"{len(listings)} folder(s) have directory listing enabled",
            "Anyone can open these folders in a browser and see/download every file inside: " + "; ".join(l["path"] for l in listings[:6]),
            "Turn off directory indexing on the web server (Options -Indexes in Apache, autoindex off in nginx) and add an empty index file to each folder.",
            [l["url"] for l in listings])
    srcdisc = dgroups.get("Source Code Disclosure", [])
    if srcdisc:
        add("critical", "Directory", f"{len(srcdisc)} server script(s) served as readable source code",
            "Raw PHP/script source is downloadable instead of being executed: " + "; ".join(s["path"] for s in srcdisc[:6]),
            "Fix the web-server handler so these extensions are executed, never served as plain text.",
            [s["url"] for s in srcdisc])
    for group, sev_default in (("Database", "critical"), ("Key / Certificate", "critical"), ("Config", "high"),
                               ("Archive", "high"), ("Backup / Temp", "high"), ("Executable", "critical"),
                               ("Log", "medium"), ("Source Map", "medium"), ("Data Export", "low")):
        items = [g for g in dgroups.get(group, [])]
        if items:
            worst = min((SEV_ORDER[i["severity"]] for i in items), default=4)
            sev = [k for k, v in SEV_ORDER.items() if v == worst][0]
            add(sev, "Directory", f"{len(items)} {group.lower()} file(s) are directly downloadable over the web",
                "; ".join(i["path"] for i in items[:6]),
                "These files should not be reachable from the browser - move them outside the web root or block the path at the server.",
                [i["url"] for i in items])

    # ---------------------------------------------------------------- action buttons (Create / Edit / Delete), read-only inventory
    action_buttons = extras.get("action_buttons") or []
    deletes = [a for a in action_buttons if a["type"] == "delete"]
    no_confirm = [a for a in deletes if not a["has_confirm"] and not a.get("has_onclick")]
    if no_confirm:
        add("high", "Action Controls", f"{len(no_confirm)} delete control(s) have no confirmation prompt",
            "No data-confirm attribute or click handler was found - nothing visibly stands between a click and the destructive action (not verified by clicking; read from the page's HTML only).",
            "Add a confirmation step before any destructive action (a confirm dialog, or a modal with an explicit Cancel).",
            [a["page"] for a in no_confirm])
    if action_buttons:
        creates, edits = [a for a in action_buttons if a["type"] == "create"], [a for a in action_buttons if a["type"] == "edit"]
        add("info", "Action Controls", f"{len(creates)} Create, {len(edits)} Edit and {len(deletes)} Delete control(s) were inventoried",
            "Read directly from each control's HTML attributes (href, data-confirm, data-method) - none were clicked, so no delete/edit/create action was ever triggered by the scan.",
            "See the Form Submissions & File Uploading tab / Action Buttons sheet for the full list.")

    # load-test insights
    load_score = None
    if stress and stress.get("ran"):
        ov = stress["overall"]
        steps = stress["steps"]
        bp = stress.get("breaking_users")
        if ov["err_rate"] > 5:
            add("critical" if ov["err_rate"] > 20 else "high", "Load", f"{ov['err_rate']:.1f}% of requests failed under load",
                "Top errors: " + ", ".join(f"{k} x{v}" for k, v in sorted(stress["errors"].items(), key=lambda kv: -kv[1])[:4]) + ".",
                "Scale up workers/DB connections, add caching, and check rate limits and timeouts.")
        elif ov["err_rate"] > 0.5:
            add("medium", "Load", f"{ov['err_rate']:.1f}% of requests failed under load", "Some errors appear at peak concurrency.", "Inspect server logs around the test window.")
        if bp:
            add("high", "Load", f"Performance degrades at ~{bp} concurrent users",
                "Latency or errors cross the safe threshold (error rate > 5% or p95 > 3x baseline / 2 s).",
                "Add horizontal scaling, caching or queueing before expected traffic reaches this level.")
        if ov["p95"] > 2000:
            add("high", "Load", f"p95 latency under peak load is {ov['p95']:.0f} ms", "Five percent of requests are slower than this.",
                "Optimise slow endpoints; add caching/CDN.")
        elif ov["p95"] > 1000:
            add("medium", "Load", f"p95 latency under peak load is {ov['p95']:.0f} ms", "Above the 1 s guideline.", "Profile slow endpoints under load.")
        worst = sorted(stress["per_page"].values(), key=lambda r: -r["p95"])[:5]
        if worst and worst[0]["p95"] > 1000:
            add("medium", "Load", "Slowest endpoints under load",
                "; ".join(f"{w['url'][:70]} p95={w['p95']:.0f} ms" for w in worst), "Start tuning with these pages.", [w["url"] for w in worst])
        if stress.get("rate_limited"):
            add("info", "Load", f"{stress['rate_limited']} requests were rate-limited (429)", "The target defends itself against bursts - good, but results are capped.",
                "Whitelist the test IP to measure true capacity.")
        # score
        load_score = 100
        load_score -= min(60, ov["err_rate"] * 3)
        load_score -= 0 if ov["p95"] < 500 else 10 if ov["p95"] < 1000 else 25 if ov["p95"] < 2000 else 40
        if bp:
            load_score -= 15
        load_score = max(0, round(load_score))

    ins.sort(key=lambda i: (SEV_ORDER[i["severity"]], -i["count"]))

    # ---------------------------------------------------------------- scores
    def per_page_perf(p):
        l = p.get("load") or 0
        s = 100 if l < 1000 else 88 if l < 2000 else 72 if l < 3000 else 55 if l < 5000 else 30
        if (p.get("lcp") or 0) > 4000: s -= 15
        elif (p.get("lcp") or 0) > 2500: s -= 7
        if (p.get("ttfb") or 0) > 800: s -= 8
        return max(0, s)
    perf = round(avg([per_page_perf(p) for p in ok_pages])) if ok_pages else 0
    bad_n = len([p for p in tested if p["status"] >= 400 and p["status"] not in (401, 403)]) + len(errs)
    rel = 100 - (100 * bad_n / max(1, len(tested) + len(errs))) - min(20, 2 * len(broken)) - min(20, 3 * len(jse))
    rel = max(0, round(rel)) if pages else 0
    seo_pen = sum(1 for i in ins if i["area"] == "SEO") * 8
    seo = max(0, 100 - seo_pen)
    acc_pen = sum(1 for i in ins if i["area"] in ("Accessibility", "Responsive")) * 10
    acc = max(0, 100 - acc_pen)
    sec_areas = ("Security", "Exposure", "Scope", "Directory", "Injection")
    sec_pen = sum({"high": 22, "medium": 12, "low": 5, "info": 0, "critical": 35}[i["severity"]] for i in ins if i["area"] in sec_areas)
    sec = max(0, 100 - sec_pen)
    form_pen = sum({"high": 15, "medium": 10, "low": 4, "info": 0, "critical": 25}[i["severity"]] for i in ins if i["area"] == "Forms")
    form_score = max(0, 100 - form_pen)
    up_pen = sum({"critical": 45, "high": 28, "medium": 14, "low": 6, "info": 0}[i["severity"]] for i in ins if i["area"] == "Upload Security")
    upload_score = max(0, 100 - up_pen)
    scores = {"Performance": perf, "Reliability": rel, "Security": sec, "SEO": seo, "Accessibility": acc}
    weights = {"Performance": 20, "Reliability": 20, "Security": 15, "SEO": 6, "Accessibility": 8, "Load Capacity": 20, "Form Validation": 5, "Upload Security": 10}
    if load_score is not None:
        scores["Load Capacity"] = load_score
    if testable_forms:
        scores["Form Validation"] = form_score
    if uploads:
        scores["Upload Security"] = upload_score
    tw = sum(weights[k] for k in scores)
    overall = round(sum(scores[k] * weights[k] for k in scores) / tw) if tw else 0

    # ---------------------------------------------------------------- narrative
    sev = Counter(i["severity"] for i in ins)
    loads = [p["load"] for p in ok_pages if p.get("load")]
    summary = [
        f"{meta['url']} was crawled across {len(pages)} URLs in {len(categories)} categories; {len(tested)} pages were fully tested"
        + (f" and {len(restricted)} were detected as login-protected but not entered." if restricted else "."),
        (f"Pages load in {avg(loads):.0f} ms on average (median {statistics.median(loads):.0f} ms, slowest {max(loads):.0f} ms)." if loads else "No page timing could be collected."),
        f"The analysis found {len(ins)} findings: {sev.get('critical', 0)} critical, {sev.get('high', 0)} high, {sev.get('medium', 0)} medium, {sev.get('low', 0)} low.",
    ]
    if stress and stress.get("ran"):
        ov = stress["overall"]
        summary.append(
            f"Under load ({stress['users']} virtual users) the site served {ov['rps']:.0f} requests/s with p95 latency {ov['p95']:.0f} ms and {ov['err_rate']:.1f}% errors"
            + (f"; degradation begins near {stress['breaking_users']} concurrent users." if stress.get("breaking_users") else "; no breaking point was reached at the tested concurrency."))
    if categories:
        worst = max((c for c in categories if c["tested"]), key=lambda c: (c["errors"], c["avg_load"]), default=None)
        if worst and (worst["errors"] or worst["avg_load"] > 2500):
            summary.append(f"The weakest section is '{worst['name']}' ({worst['errors']} error pages, average load {worst['avg_load']:.0f} ms).")
    if testable_forms:
        summary.append(f"{len(testable_forms)} form(s) across the site were filled with clearly-marked test_ data and submitted"
                       + (f"; {len(no_client_validation)} had no client-side validation on required fields." if no_client_validation else "."))
    if uploads:
        bad_up = len(rce) + len(disguised_accepted) + len(traversal_accepted)
        summary.append(f"{len(uploads)} file-upload test(s) were run" + (f"; {bad_up} raised upload-security concerns." if bad_up else "; no unsafe uploads were accepted."))
    if exposure_findings:
        crit_high = sum(1 for e in exposure_findings if e["severity"] in ("critical", "high"))
        summary.append(f"The unauthenticated exposure scan found {len(exposure_findings)} publicly reachable sensitive path(s)"
                       + (f", {crit_high} of them critical/high severity." if crit_high else "."))
    if fs_result and fs_result.get("ok"):
        summary.append(f"The local project folder scan checked {fs_result['files_scanned']} files in {fs_result['dirs_scanned']} folders"
                       + (f" and found {len(local_findings)} risky file(s) on disk." if local_findings else " and found nothing risky on disk."))
    if action_buttons:
        summary.append(f"{len(action_buttons)} Create/Edit/Delete control(s) were inventoried from the page HTML (never clicked)"
                       + (f"; {len(no_confirm)} delete control(s) showed no confirmation step." if no_confirm else "."))
    top = [i for i in ins if i["severity"] in ("critical", "high")][:3]
    if top:
        summary.append("Priority fixes: " + "; ".join(i["title"] for i in top) + ".")
    verdict = ("Production-ready" if overall >= 85 and not sev.get("critical") and not sev.get("high")
               else "Needs attention" if overall >= 65 and not sev.get("critical") else "At risk")

    return {
        "meta": meta, "scores": scores, "overall": overall, "grade": grade(overall), "verdict": verdict,
        "summary": summary, "insights": ins, "categories": categories, "broken_links": broken,
        "pages": pages, "stress": stress, "external": extras.get("external", []),
        "forms": forms, "uploads": uploads,
        "exposure": {"findings": exposure_findings, "counts": dict(Counter(e["severity"] for e in exposure_findings))},
        "local_files": {"result": fs_result, "findings": local_findings, "web_sweep_checked": extras.get("web_sweep_checked", 0)},
        "directory_scan": _dscan_report(extras.get("directory_scan") or {}),
        "dir_tree": _assemble_tree(fs_result, local_findings, extras.get("directory_scan") or {}),
        "sql_findings": sql_findings, "speed": extras.get("speed", "normal"),
        "action_buttons": action_buttons,
        "scope": {"base_url": extras.get("base_url"), "out_of_base": out_of_base, "total_calls": extras.get("total_calls", 0)},
        "kpis": {
            "urls": len(pages), "tested": len(tested), "categories": len(categories),
            "avg_load": avg(loads), "p95_load": round(pct(loads, 95), 1),
            "errors": len(s5) + len(s4) + len(errs), "broken_links": len(broken),
            "console_errors": sum(len(p.get("console_errors", [])) + len(p.get("page_errors", [])) for p in tested),
            "restricted": len(restricted), "findings": len(ins),
            "total_mb": round(sum(p.get("size_kb") or 0 for p in tested) / 1024, 2),
            "forms_tested": len(testable_forms), "uploads_tested": len(uploads),
            "exposure_critical": sum(1 for e in exposure_findings if e["severity"] == "critical"),
            "local_risky_files": len(local_findings), "action_buttons": len(action_buttons),
        },
    }
