"""Crawl + functional/performance test engine (Playwright, async, multi-worker)."""
from __future__ import annotations

import asyncio
import os
import re
import time
import xml.etree.ElementTree as ET
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx
from playwright.async_api import async_playwright

import analyzer
import exposure
import fsaudit
from formtest import FormTester
from loadtest import run_load

SKIP_EXT = (".pdf", ".zip", ".rar", ".7z", ".gz", ".tar", ".exe", ".msi", ".dmg", ".apk", ".jpg", ".jpeg", ".png",
            ".gif", ".svg", ".webp", ".ico", ".bmp", ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".webm", ".css", ".js",
            ".map", ".json", ".xml", ".txt", ".csv", ".xls", ".xlsx", ".doc", ".docx", ".ppt", ".pptx", ".woff",
            ".woff2", ".ttf", ".eot", ".rss")
# never visited: could change state (we only ever perform GET navigations anyway)
DANGEROUS = re.compile(r"(log-?out|sign-?out|log-?off|delete|remove|destroy|unsubscribe|deactivate|revoke|disconnect|"
                       r"cancel[-_]?account|purge|truncate|wipe|reset[-_]?all)", re.I)
LOGIN_URL = re.compile(r"(login|log-in|signin|sign-in|sso|wp-login|auth(?!or)|session/new)", re.I)
REGISTER_URL = re.compile(r"(register|signup|sign-up|join|create[-_]account)", re.I)
TRACKING = re.compile(r"^(utm_|fbclid|gclid|_ga|mc_|ref$)", re.I)
PAGINATION_KEYS = {"page", "p", "offset", "start", "pg", "pagenum", "page_num"}

# speed profiles - tune how much per-page work the crawler does
SPEED_PROFILES = {
    "normal": {"workers_cap": 8, "screenshots": "all", "responsive": True, "networkidle": True,
               "expand_menus": True, "click_discovery": True, "settle_idle_ms": 1400, "forms": True},
    "fast":   {"workers_cap": 10, "screenshots": "issues", "responsive": False, "networkidle": False,
               "expand_menus": True, "click_discovery": False, "settle_idle_ms": 500, "forms": True},
    "ultra":  {"workers_cap": 16, "screenshots": "none", "responsive": False, "networkidle": False,
               "expand_menus": False, "click_discovery": False, "settle_idle_ms": 0, "forms": False},
}

# database error signatures -> error-based SQL-injection / DB-leak detection (read-only, passive)
SQL_ERROR_RE = re.compile(
    r"(SQL syntax.{0,40}MySQL|You have an error in your SQL syntax|Warning.{0,20}mysqli?_|Warning.{0,20}pg_|"
    r"PostgreSQL.{0,20}ERROR|SQLSTATE\[|ORA-\d{5}|Microsoft OLE DB Provider for SQL Server|"
    r"Unclosed quotation mark after the character string|quoted string not properly terminated|"
    r"SQLiteException|sqlite3.OperationalError|near \".*\": syntax error|"
    r"Incorrect syntax near|Column count doesn't match|supplied argument is not a valid MySQL|"
    r"Yii\\\\db\\\\Exception|CDbCommand failed to execute|yii\\db\\Exception)", re.I)

HAS_VISIBLE_PW = """() => [...document.querySelectorAll('input[type=password]')].some(e => {
  const r = e.getBoundingClientRect(); const s = getComputedStyle(e);
  return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none'; })"""

LOGIN_FIELDS_JS = """() => {
  const vis = e => { const r = e.getBoundingClientRect(); const s = getComputedStyle(e);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none'; };
  const pw = [...document.querySelectorAll('input[type=password]')].find(vis);
  if (!pw) return [];
  const root = pw.closest('form') || pw.parentElement.parentElement.parentElement || document.body;
  const skip = ['hidden','submit','button','checkbox','radio','image','file','reset'];
  const inputs = [...root.querySelectorAll('input,select,textarea')].filter(e => vis(e) && !skip.includes(e.type));
  inputs.forEach((e, i) => e.setAttribute('data-st-i', i));
  return inputs.map((e, i) => ({ i, type: e.type || e.tagName.toLowerCase(), name: e.name || e.id || '',
    label: ((e.labels && e.labels[0]) ? e.labels[0].innerText : '') || e.placeholder || e.getAttribute('aria-label') || e.name || e.id || e.type,
    secret: e.type === 'password' }));
}"""

EXPAND_MENUS_JS = """() => {
  const DANGER = /(log-?out|sign-?out|delete|remove|destroy|unsubscribe|deactivate|cancel)/i;
  const sels = ['[aria-expanded="false"]', '[data-toggle="collapse"]', '[data-bs-toggle="collapse"]', '.has-treeview > a',
    '[data-widget="treeview"] a.nav-link', '.nav-item > a.dropdown-toggle', '.nav-item.has-treeview > a', '.sidebar-menu .treeview > a'];
  let n = 0;
  const seen = new Set();
  document.querySelectorAll(sels.join(',')).forEach(el => {
    if (seen.has(el)) return; seen.add(el);
    const href = (el.getAttribute('href') || '').trim();
    if (href && href !== '#' && !href.toLowerCase().startsWith('javascript:')) return;   // a real link, not a pure toggle
    const text = (el.innerText || '').trim();
    if (DANGER.test(text) || DANGER.test(el.className || '')) return;
    const r = el.getBoundingClientRect();
    if (r.width === 0 || r.height === 0) return;
    el.click(); n++;
  });
  return n;
}"""

LOGIN_ERR_JS = """() => [...document.querySelectorAll('.error,.alert,.alert-danger,[role=alert],.invalid-feedback,.text-danger,.help-block,.notification,.message,.flash')]
  .map(x => (x.innerText || '').trim()).filter(Boolean).slice(0, 3).join(' | ')"""

INSPECT_JS = """() => new Promise(resolve => {
  let lcp = 0, cls = 0;
  try { new PerformanceObserver(l => { for (const e of l.getEntries()) lcp = e.startTime; }).observe({type: 'largest-contentful-paint', buffered: true}); } catch (e) {}
  try { new PerformanceObserver(l => { for (const e of l.getEntries()) if (!e.hadRecentInput) cls += e.value; }).observe({type: 'layout-shift', buffered: true}); } catch (e) {}
  setTimeout(() => {
    const nav = performance.getEntriesByType('navigation')[0] || {};
    const res = performance.getEntriesByType('resource');
    const paint = performance.getEntriesByType('paint').find(p => p.name === 'first-contentful-paint');
    const vis = e => { const r = e.getBoundingClientRect(); const s = getComputedStyle(e);
      return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none'; };
    const area = a => a.closest('nav,[role=navigation],.navbar,.nav,.menu,.sidebar,aside') ? 'nav'
      : a.closest('header') ? 'header' : a.closest('footer') ? 'footer' : 'content';
    const urlFromJs = s => { if (!s) return '';
      const pats = [/location\\.href\\s*=\\s*['"]([^'"]+)['"]/, /window\\.location(?:\\.href)?\\s*=\\s*['"]([^'"]+)['"]/,
        /\\blocation\\s*=\\s*['"]([^'"]+)['"]/, /\\$\\.pjax\\(\\s*\\{[^}]*url\\s*:\\s*['"]([^'"]+)['"]/,
        /\\bpjax\\(\\s*['"]([^'"]+)['"]/, /loadUrl\\(\\s*['"]([^'"]+)['"]/, /loadContent\\(\\s*['"]([^'"]+)['"]/,
        /\\bajax\\(\\s*\\{[^}]*url\\s*:\\s*['"]([^'"]+)['"]/, /\\bopen\\(\\s*['"]([^'"]+)['"]/];
      for (const re of pats) { const m = s.match(re); if (m) return m[1]; } return ''; };
    const linkEls = [...document.querySelectorAll('a,[data-href],[data-url],[data-pjax-url],[data-link],area[href],[onclick]')];
    const links = linkEls.map(a => {
      let href = (typeof a.href === 'string' ? a.href : '') || a.getAttribute('data-href') || a.getAttribute('data-url') ||
        a.getAttribute('data-pjax-url') || a.getAttribute('data-link') || '';
      if (!href || href === '#' || href.toLowerCase().startsWith('javascript:')) href = urlFromJs(a.getAttribute('onclick') || '') || href;
      return { href, text: (a.innerText || a.title || a.getAttribute('aria-label') || '').trim().replace(/\\s+/g, ' ').slice(0, 60), area: area(a) };
    }).filter(l => l.href && l.href !== '#' && !l.href.toLowerCase().startsWith('javascript:'));
    const meta = n => { const m = document.querySelector('meta[name="' + n + '"]'); return m ? (m.content || '') : ''; };
    const imgs = [...document.images];
    const ctrls = [...document.querySelectorAll('button,[role=button],a[href]')];
    const inputs = [...document.querySelectorAll('input:not([type=hidden]):not([type=submit]):not([type=button]),select,textarea')];
    const sum = (a, k) => a.reduce((t, x) => t + (x[k] || 0), 0);
    resolve({
      ttfb: nav.responseStart || 0, dcl: nav.domContentLoadedEventEnd || 0, load: nav.loadEventEnd || nav.domContentLoadedEventEnd || 0,
      fcp: paint ? paint.startTime : 0, lcp, cls: Math.round(cls * 1000) / 1000,
      transfer: sum(res, 'transferSize') + (nav.transferSize || 0), decoded: sum(res, 'decodedBodySize') + (nav.decodedBodySize || 0),
      doc_enc: nav.encodedBodySize || 0, doc_dec: nav.decodedBodySize || 0, nres: res.length + 1,
      mixed: location.protocol === 'https:' ? res.filter(r => r.name.startsWith('http:')).length : 0,
      title: document.title || '', desc: meta('description'), h1: document.querySelectorAll('h1').length,
      canonical: !!document.querySelector('link[rel=canonical]'), viewport: !!meta('viewport'),
      lang: document.documentElement.lang || '', dom: document.getElementsByTagName('*').length,
      imgs: imgs.length, img_no_alt: imgs.filter(i => !i.hasAttribute('alt')).length,
      img_broken: imgs.filter(i => i.complete && i.naturalWidth === 0 && i.src && !i.src.startsWith('data:')).length,
      forms: document.forms.length, inputs: inputs.length, buttons: document.querySelectorAll('button,input[type=submit],[role=button]').length,
      buttons_no_name: ctrls.filter(c => vis(c) && !(c.innerText || '').trim() && !c.getAttribute('aria-label') && !c.title && !c.querySelector('img[alt]')).length,
      inputs_no_label: inputs.filter(i => vis(i) && !(i.labels && i.labels.length) && !i.getAttribute('aria-label') && !i.getAttribute('aria-labelledby') && !i.title).length,
      scripts: document.scripts.length, text_len: (document.body ? document.body.innerText.length : 0),
      has_pw: [...document.querySelectorAll('input[type=password]')].filter(vis).length, links });
  }, 60);
})"""


ACTION_BUTTONS_JS = """() => {
  const vis = e => { const r = e.getBoundingClientRect(); const s = getComputedStyle(e);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none'; };
  const els = [...document.querySelectorAll('a, button, input[type=submit], input[type=button]')].filter(vis);
  const out = []; const seen = new Set();
  for (const el of els) {
    const text = (el.innerText || el.value || el.title || el.getAttribute('aria-label') || '').trim();
    const cls = (el.className || '').toString();
    const iconEl = el.querySelector('i,svg'); const icon = iconEl ? (iconEl.className || '').toString() : '';
    const blob = (text + ' ' + cls + ' ' + icon).toLowerCase();
    let type = null;
    if (/\\bdelete\\b|\\bremove\\b|fa-trash|glyphicon-trash|icon-trash/.test(blob)) type = 'delete';
    else if (/\\bedit\\b|\\bupdate\\b|fa-edit|fa-pencil|glyphicon-edit|glyphicon-pencil/.test(blob)) type = 'edit';
    else if (/\\bcreate\\b|\\badd\\s*new\\b|fa-plus|glyphicon-plus|\\bnew\\b/.test(blob)) type = 'create';
    if (!type) continue;
    const href = el.getAttribute('href') || '';
    const confirm = el.getAttribute('data-confirm') || '';
    const method = el.getAttribute('data-method') || '';
    const onclick = el.getAttribute('onclick') || '';
    const key = type + '|' + href.replace(/\\d+/g, '#') + '|' + text.slice(0, 24);
    if (seen.has(key)) continue; seen.add(key);
    out.push({ type, label: text.slice(0, 60) || type, href, has_confirm: !!confirm, confirm_message: confirm.slice(0, 220),
      method: method.toLowerCase(), has_onclick: !!onclick });
  }
  return out.slice(0, 60);
}"""


NAV_CLICK_JS = """() => {
  const vis = e => { const r = e.getBoundingClientRect(); const s = getComputedStyle(e);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none'; };
  const hasUsableHref = el => {
    const href = (el.getAttribute && (el.getAttribute('href') || el.getAttribute('data-href') || el.getAttribute('data-url') ||
      el.getAttribute('data-pjax-url') || el.getAttribute('data-link'))) || '';
    return !!(href && href !== '#' && !href.toLowerCase().startsWith('javascript:'));
  };
  const DANGER = /(log-?out|sign-?out|delete|remove|destroy|unsubscribe|deactivate|cancel)/i;
  const containers = [...document.querySelectorAll('nav, .navbar, .sidebar, .main-sidebar, .main-header, header, [role="navigation"], .nav-sidebar, .topnav, .top-nav, .navbar-nav')];
  const scope = containers.length ? containers : [document.body];
  const seen = new Set(); const out = [];
  for (const root of scope) {
    const els = [...root.querySelectorAll('a, button, [role="button"], li[onclick], span[onclick], div[onclick]')].filter(vis);
    for (const el of els) {
      if (hasUsableHref(el)) continue;
      if (el.getAttribute('data-method') || el.getAttribute('data-confirm')) continue;   // action control, not navigation
      if (el.closest('form') && (el.type === 'submit' || el.tagName === 'BUTTON')) continue;
      const text = (el.innerText || el.title || el.getAttribute('aria-label') || '').trim().replace(/\\s+/g, ' ').slice(0, 60);
      if (!text) continue;
      if (DANGER.test(text) || DANGER.test(el.className || '')) continue;
      const key = text + '|' + (el.className || '').toString().slice(0, 40);
      if (seen.has(key)) continue; seen.add(key);
      out.push({ text });
    }
  }
  return out.slice(0, 30);
}"""


def norm(url: str, base: str | None = None) -> str | None:
    try:
        if base:
            url = urljoin(base, url)
        p = urlparse(url.strip())
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or not p.netloc:
        return None
    frag = p.fragment if p.fragment.startswith(("/", "!/")) else ""
    q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if not TRACKING.match(k)]
    host = p.netloc.lower()
    for dflt in (":80", ":443"):
        if host.endswith(dflt) and ((dflt == ":80") == (p.scheme == "http")):
            host = host[: -len(dflt)]
    path = re.sub(r"/{2,}", "/", p.path or "/")
    return urlunparse((p.scheme, host, path, "", urlencode(q), frag))


class Scanner:
    def __init__(self, job_id: str, start_url: str, opts: dict, outdir: str, emit):
        self.id = job_id
        self.start = norm(start_url) or start_url
        self.o = opts
        self.dir = outdir
        self.shots = os.path.join(outdir, "shots")
        os.makedirs(self.shots, exist_ok=True)
        self._emit = emit
        self.host = urlparse(self.start).netloc.lower()
        self.base_host = self.host.removeprefix("www.")
        self.pages: dict[str, dict] = {}
        self.seen: set[str] = set()
        self.finals: dict[str, str] = {}
        self.queue: asyncio.Queue = asyncio.Queue()
        self.query_count: dict[tuple, int] = {}
        self.external: dict[str, set] = {}
        self.skipped_links: set[str] = set()
        self.halt_all = False
        self.halt_phase = False
        self.auth_state = "unknown"          # unknown | pending | ok | skipped
        self.auth_lock = asyncio.Lock()
        self.login_future: asyncio.Future | None = None
        self.login_seq = 0
        self.cookies: list[dict] = []
        self.auth_header = ""
        self.cur: dict[int, dict] = {}
        self.seq = 0
        self.stress: dict | None = None
        self.ctx = None
        self.crawl_limited = False
        self.ext_result: dict[str, dict] = {}
        self.t_start = time.time()
        base_url = (opts.get("base_url") or "").strip()
        bu = norm(base_url) if base_url else None
        self.base_url = bu
        self.base_path = (urlparse(bu).path.rstrip("/") + "/") if bu else None
        self.all_calls: list[dict] = []
        self.out_of_base: list[dict] = []
        self.exposure: list[dict] = []
        self.fs_result: dict | None = None
        self.action_buttons: list[dict] = []
        self.web_sweep_checked = 0
        self.directory_scan: dict | None = None
        self.speed = (opts.get("speed") or "normal").lower()
        if self.speed not in SPEED_PROFILES:
            self.speed = "normal"
        self.sp = SPEED_PROFILES[self.speed]
        self.sql_findings: list[dict] = []
        self.sql_tested: set[str] = set()
        self.phases: list[str] = []

    # ------------------------------------------------------------------ helpers
    def emit(self, ev: dict, store: bool = True):
        self._emit(ev, store)

    def log(self, msg: str, level: str = "info"):
        self.emit({"type": "log", "level": level, "msg": msg, "t": round(time.time() - self.t_start, 1)})

    def in_scope(self, url: str) -> bool:
        return urlparse(url).netloc.lower().removeprefix("www.") == self.base_host

    def request_stop(self, phase_only: bool = False):
        if phase_only:
            self.halt_phase = True
        else:
            self.halt_all = True
        if self.login_future and not self.login_future.done():
            self.login_future.set_result({"skip": True})

    def provide_login(self, payload: dict):
        if self.login_future and not self.login_future.done():
            self.login_future.set_result(payload)
            return True
        return False

    def public(self, rec: dict) -> dict:
        """Lightweight record for live UI updates."""
        keys = ("id", "url", "final_url", "category", "depth", "parent", "state", "status", "title", "load", "ttfb", "lcp",
                "size_kb", "requests", "shot", "error", "alias_of", "link_text", "area", "requires_login", "is_login",
                "n_console", "n_failed")
        d = {k: rec.get(k) for k in keys}
        d["n_console"] = len(rec.get("console_errors", [])) + len(rec.get("page_errors", []))
        d["n_failed"] = len(rec.get("failed_requests", []))
        return d

    def add_page(self, url: str, depth: int, parent: str | None, text: str = "", area: str = "") -> bool:
        if url in self.seen or len(self.pages) >= self.o["max_pages"]:
            if url not in self.seen and len(self.pages) >= self.o["max_pages"]:
                self.crawl_limited = True
            return False
        pq = urlparse(url)
        if pq.query:
            # Only guard against a genuine pagination trap (?page=1, ?page=2, ... ?page=99999): key on the
            # path PLUS every non-pagination query param, so front-controller apps (index.php?r=controller/action,
            # everything behind one path) are never capped - each distinct route/filter combo gets its own budget.
            qs = parse_qsl(pq.query, keep_blank_values=True)
            has_numeric_pg = any(k.lower() in PAGINATION_KEYS and v.isdigit() for k, v in qs)
            if has_numeric_pg:
                rest = tuple(sorted((k, v) for k, v in qs if k.lower() not in PAGINATION_KEYS))
                key = (pq.netloc + pq.path, rest)
                self.query_count[key] = self.query_count.get(key, 0) + 1
                if self.query_count[key] > 6:
                    return False
        self.seen.add(url)
        self.seq += 1
        rec = {"id": self.seq, "url": url, "final_url": url, "depth": depth, "parent": parent, "link_text": text, "area": area,
               "state": "queued", "category": analyzer.category_for(url), "children": [], "child_text": {},
               "console_errors": [], "page_errors": [], "failed_requests": []}
        self.pages[url] = rec
        self.queue.put_nowait(url)
        self.emit({"type": "page", "page": self.public(rec)})
        return True

    # ------------------------------------------------------------------ main phases
    async def run(self) -> dict:
        do_dir = self.o.get("scan_exposure", True) or bool((self.o.get("project_path") or "").strip())
        do_links = self.o.get("crawl_links", True)
        # clear sequential phases: 1) Directory fully first, 2) Links, 3) Forms (inside the crawl)
        self.phases = [p for p, on in (("directory", do_dir), ("links", do_links),
                                       ("forms", do_links and self.o.get("test_forms")),
                                       ("stress", do_links and self.o.get("stress"))) if on]
        self.emit({"type": "phases", "phases": self.phases})
        if do_dir:
            self.emit({"type": "phase_begin", "phase": "directory", "msg": "Phase 1 — Complete directory scan"})
            self.exposure = await self._scan_exposure()
            self.emit({"type": "phase_done", "phase": "directory"})
        if do_links and not self.halt_all:
            self.emit({"type": "phase_begin", "phase": "links", "msg": "Phase 2 — Link discovery & testing"})
            self.emit({"type": "status", "phase": "crawling", "msg": f"Launching crawl engine ({self.speed} mode)"})
            if self.speed == "ultra":
                await self._crawl_http()
            else:
                await self._crawl()
            self.emit({"type": "phase_done", "phase": "links"})
            if not self.halt_all:
                self.emit({"type": "phase_begin", "phase": "forms", "msg": "Phase 3 — Form validation & submission"})
                await self._security_scan()
                await self._check_external()
                self.emit({"type": "phase_done", "phase": "forms"})
            if self.o.get("stress") and not self.halt_all:
                await self._stress()
        if self.base_path:
            self.out_of_base = [c for c in self.all_calls if not urlparse(c["url"]).path.startswith(self.base_path)]
        self.emit({"type": "status", "phase": "analyzing", "msg": "Building intelligent report"})
        meta = {"url": self.start, "job": self.id, "started": self.t_start, "duration_s": round(time.time() - self.t_start, 1),
                "max_pages": self.o["max_pages"], "workers": self.o["workers"], "viewport": "1920x1080",
                "authenticated": self.auth_state == "ok", "stress_enabled": bool(self.o.get("stress")),
                "skipped_unsafe_links": len(self.skipped_links), "base_url": self.base_url, "modes": self.o.get("modes")}
        ext = [{"url": u, "sources": sorted(s)[:5], **self.ext_result[u]} for u, s in self.external.items() if u in self.ext_result]
        return analyzer.build_report(meta, list(self.pages.values()), self.stress,
                                     {"external": ext, "cookie_issues": self._cookie_issues(), "crawl_limited": self.crawl_limited,
                                      "exposure": self.exposure, "out_of_base": self.out_of_base[:200], "base_url": self.base_url,
                                      "total_calls": len(self.all_calls), "fs_result": self.fs_result, "action_buttons": self.action_buttons,
                                      "web_sweep_checked": self.web_sweep_checked, "directory_scan": self.directory_scan,
                                      "sql_findings": self.sql_findings, "speed": self.speed})

    def snapshot_report(self) -> dict | None:
        """A cheap partial report built from whatever has been collected so far, for live updates."""
        if not self.pages and not self.exposure and not self.directory_scan:
            return None
        try:
            if self.base_path:
                out_of_base = [c for c in self.all_calls if not urlparse(c["url"]).path.startswith(self.base_path)]
            else:
                out_of_base = []
            meta = {"url": self.start, "job": self.id, "started": self.t_start, "duration_s": round(time.time() - self.t_start, 1),
                    "max_pages": self.o["max_pages"], "workers": self.o["workers"], "viewport": "1920x1080",
                    "authenticated": self.auth_state == "ok", "stress_enabled": bool(self.o.get("stress")),
                    "skipped_unsafe_links": len(self.skipped_links), "base_url": self.base_url}
            # live snapshots go out every few seconds - drop the big filesystem inventory / scanned list to
            # keep them small (the full report sent on completion has everything)
            light_dscan = self.directory_scan
            if light_dscan and (light_dscan.get("all_items") or light_dscan.get("scanned")):
                light_dscan = {**light_dscan, "all_items": [], "scanned": []}
            rep = analyzer.build_report(meta, list(self.pages.values()), self.stress,
                                        {"external": [], "cookie_issues": self._cookie_issues(), "crawl_limited": self.crawl_limited,
                                         "exposure": self.exposure, "out_of_base": out_of_base[:200], "base_url": self.base_url,
                                         "total_calls": len(self.all_calls), "fs_result": self.fs_result, "action_buttons": self.action_buttons,
                                         "web_sweep_checked": self.web_sweep_checked, "directory_scan": light_dscan,
                                         "sql_findings": self.sql_findings, "speed": self.speed})
            if rep.get("directory_scan"):
                rep["directory_scan"]["all_items"] = []
                rep["directory_scan"]["scanned"] = []
            rep["dir_tree"] = {"name": "/", "path": "", "children": [], "issues": [], "severity": None, "count": 0}
            return rep
        except Exception:  # noqa: BLE001
            return None

    HREF_RE = re.compile(r'''(?:href|data-href|data-url|data-pjax-url|action)\s*=\s*["']([^"'<>]+)["']''', re.I)
    ONCLICK_RE = re.compile(r'''(?:location(?:\.href)?|window\.location(?:\.href)?)\s*=\s*["']([^"'<>]+)["']''', re.I)

    async def _seed(self):
        """Seed the crawl queue - normally just the start URL + sitemap; for a 'Rescan flagged' run,
        only the specific flagged URLs, with no link-following (depth 0), to verify fixes quickly."""
        rescan = self.o.get("rescan_urls") or []
        if rescan:
            self.o["max_depth"] = 0
            n = 0
            for u in rescan:
                nu = norm(u)
                if nu and self.in_scope(nu) and self.add_page(nu, 0, None, "rescan", "rescan"):
                    n += 1
            self.log(f"Rescan mode: re-testing {n} previously-flagged link(s) only.")
            return
        self.add_page(self.start, 0, None)
        await self._seed_sitemap()

    async def _browser_login(self):
        """Ultra mode: spin up the browser just long enough to pass any login wall and capture the
        session cookies, then hand off to the fast browserless HTTP crawl."""
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True, args=["--disable-gpu", "--mute-audio", "--no-sandbox"])
            self.ctx = await browser.new_context(viewport={"width": 1920, "height": 1080}, ignore_https_errors=True)
            self.ctx.set_default_timeout(15000)
            page = await self.ctx.new_page()
            page.on("dialog", lambda d: asyncio.ensure_future(d.dismiss()))
            self.cur[0] = self._fresh_cur()
            await self._start_stream(0, page)
            try:
                await page.goto(self.start, wait_until="domcontentloaded", timeout=self.o.get("timeout", 30) * 1000)
                await self._settle(page)
                walled = await page.evaluate(HAS_VISIBLE_PW)
                if not walled:
                    # home may be public - follow a few in-scope links to find the login wall
                    links = await page.evaluate(
                        "() => [...document.querySelectorAll('a[href]')].map(a => a.href).slice(0, 60)")
                    tried = 0
                    for href in links:
                        nu = norm(href, page.url)
                        if not nu or not self.in_scope(nu) or nu == self.start or DANGEROUS.search(urlparse(nu).path):
                            continue
                        try:
                            await page.goto(nu, wait_until="domcontentloaded", timeout=12000)
                            await self._settle(page)
                        except Exception:  # noqa: BLE001
                            continue
                        if await page.evaluate(HAS_VISIBLE_PW):
                            walled = True
                            break
                        tried += 1
                        if tried >= 4:
                            break
                if walled:
                    rec = {"id": 0, "url": page.url, "final_url": page.url, "category": "Authentication"}
                    await self._do_login(0, page, rec)
            except Exception as e:  # noqa: BLE001
                self.log(f"Login step failed: {type(e).__name__}: {e}", "warn")
            try:
                self.cookies = await self.ctx.cookies()
            except Exception:  # noqa: BLE001
                self.cookies = []
            await browser.close()
            self.ctx = None

    async def _crawl_http(self):
        """Browserless, high-concurrency link enumeration + security checks (Ultra Fast). No screenshots,
        no JS, no form testing - just status, headers, links, and passive DB-error detection, as fast as
        the server will answer. Logs in first (via a throwaway browser) so authenticated pages are reachable."""
        await self._browser_login()
        if self.halt_all:
            return
        await self._seed()
        headers = {"User-Agent": "StressScope/1.0 (authorised fast scan)", "Accept": "text/html,*/*;q=0.8"}
        ck = self._cookie_header()
        if ck:
            headers["Cookie"] = ck
        n = min(int(self.o["workers"]) * 3, 40)
        limits = httpx.Limits(max_connections=n + 10, max_keepalive_connections=n + 10)
        self.emit({"type": "status", "phase": "crawling", "msg": f"Ultra-fast HTTP crawl: {n} parallel fetchers, no browser"})
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=self.o.get("timeout", 30),
                                     headers=headers, limits=limits) as client:
            workers = [asyncio.create_task(self._http_worker(client)) for _ in range(n)]
            joiner = asyncio.create_task(self.queue.join())
            while not joiner.done():
                if self.halt_all or self.halt_phase:
                    while not self.queue.empty():
                        try:
                            u = self.queue.get_nowait()
                            self.pages[u]["state"] = "skipped"
                            self.queue.task_done()
                        except asyncio.QueueEmpty:
                            break
                await asyncio.sleep(0.2)
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
        self.halt_phase = False

    async def _http_worker(self, client):
        while True:
            try:
                url = await self.queue.get()
            except asyncio.CancelledError:
                break
            try:
                if not (self.halt_all or self.halt_phase):
                    await self._visit_http(client, url)
                else:
                    self.pages[url]["state"] = "skipped"
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                self.pages[url].update(state="error", error=f"{type(e).__name__}: {str(e)[:140]}")
                self.emit({"type": "page", "page": self.public(self.pages[url])})
            finally:
                self.queue.task_done()

    async def _visit_http(self, client, url):
        rec = self.pages[url]
        rec["state"] = "testing"
        self.emit({"type": "page", "page": self.public(rec)})
        t0 = time.perf_counter()
        try:
            r = await client.get(url)
        except Exception as e:  # noqa: BLE001
            rec.update(state="error", error=str(e).split("\n")[0][:160], load=round((time.perf_counter() - t0) * 1000))
            self.emit({"type": "page", "page": self.public(rec)})
            return
        wall = round((time.perf_counter() - t0) * 1000)
        final = norm(str(r.url)) or str(r.url)
        ctype = r.headers.get("content-type", "").lower()
        h = r.headers
        rec.update(status=r.status_code, final_url=final, load=wall, ttfb=wall, size_kb=round(len(r.content) / 1024, 1),
                   requests=1, content_type=ctype.split(";")[0],
                   compressed=bool(h.get("content-encoding")),
                   sec_headers={"hsts": "strict-transport-security" in h, "csp": "content-security-policy" in h,
                                "xfo": "x-frame-options" in h or "frame-ancestors" in h.get("content-security-policy", ""),
                                "xcto": "x-content-type-options" in h, "refpol": "referrer-policy" in h,
                                "server_disclosure": next((f"{k}: {h[k]}" for k in ("x-powered-by", "server") if k in h and re.search(r"\d", h[k])), "")})
        owner = self.finals.get(final)
        if owner and owner != url:
            rec.update(state="done", alias_of=owner, category=self.pages[owner]["category"])
            self.emit({"type": "page", "page": self.public(rec)})
            return
        self.finals.setdefault(final, url)
        self.seen.add(final)
        rec["category"] = analyzer.category_for(final)
        body = r.text if "html" in ctype or not ctype else ""
        if body and SQL_ERROR_RE.search(body[:120000]):
            f = {"url": url, "param": "(page)", "test_url": url, "evidence": "DB error text present in the normal page response", "path": urlparse(url).path}
            if urlparse(url).path not in self.sql_tested:
                self.sql_tested.add(urlparse(url).path)
                self.sql_findings.append(f)
                self.emit({"type": "sqli_hit", "finding": f})
        # link extraction (server-rendered HTML)
        if "html" in ctype and rec["depth"] < self.o.get("max_depth", 12):
            hrefs = set(self.HREF_RE.findall(body)) | set(self.ONCLICK_RE.findall(body))
            rec["children"] = []
            for href in hrefs:
                nu = norm(href, final)
                if not nu or nu == url:
                    continue
                if not self.in_scope(nu):
                    self.external.setdefault(nu.split("#")[0], set()).add(url)
                    continue
                if nu.split("#")[0].lower().endswith(SKIP_EXT) and "#/" not in nu:
                    continue
                if DANGEROUS.search(urlparse(nu).path + "?" + urlparse(nu).query):
                    self.skipped_links.add(nu)
                    continue
                rec["children"].append(nu)
                self.add_page(nu, rec["depth"] + 1, url, "", "content")
            rec["children"] = list(dict.fromkeys(rec["children"]))
        rec["state"] = "done"
        self.emit({"type": "page", "page": self.public(rec)})

    def _cookie_header(self) -> str:
        hostname = self.host.split(":")[0]
        return "; ".join(f"{c['name']}={c['value']}" for c in self.cookies
                         if hostname == c["domain"].lstrip(".") or hostname.endswith("." + c["domain"].lstrip(".")))

    async def _security_scan(self):
        """Safe, read-only error-based SQL-injection detection: for each unique parameterised endpoint,
        fetch it normally, then fetch it once with a single quote appended to one value, and compare. A
        database error that appears only in the quoted request signals unsanitised input. GET-only; no
        destructive payloads, no UNION/stacked queries, no automated exploitation."""
        if not self.o.get("check_sqli", True):
            return
        targets: dict[str, dict] = {}
        for p in self.pages.values():
            if p.get("state") != "done" or p.get("alias_of") or (p.get("status") or 0) >= 400:
                continue
            u = p["url"]
            pr = urlparse(u)
            qs = [(k, v) for k, v in parse_qsl(pr.query, keep_blank_values=True) if k.lower() not in PAGINATION_KEYS]
            if not qs:
                continue
            sig = pr.path + "|" + ",".join(sorted(k for k, _ in qs))
            if sig not in targets:
                targets[sig] = {"url": u, "params": qs, "path": pr.path}
        targets = dict(list(targets.items())[:400])
        if not targets:
            return
        self.emit({"type": "status", "phase": "security", "msg": f"Security check: probing {len(targets)} parameterised endpoint(s) for SQL-injection error leaks"})
        headers = {"User-Agent": "StressScope/1.0 (authorised security test)"}
        ck = self._cookie_header()
        if ck:
            headers["Cookie"] = ck
        sem = asyncio.Semaphore(20)

        async def probe(t):
            if self.halt_all:
                return
            pr = urlparse(t["url"])
            async with sem:
                try:
                    async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True, headers=headers) as c:
                        base = await c.get(t["url"])
                        base_err = bool(SQL_ERROR_RE.search(base.text[:120000]))
                        # inject a single quote into the first non-pagination parameter
                        inj = dict(t["params"])
                        k0 = t["params"][0][0]
                        inj[k0] = t["params"][0][1] + "'"
                        q = urlencode([(k, inj.get(k, v)) for k, v in t["params"]])
                        test_url = urlunparse((pr.scheme, pr.netloc, pr.path, "", q, ""))
                        r = await c.get(test_url)
                        hit = SQL_ERROR_RE.search(r.text[:120000])
                        if hit and not base_err:
                            m = hit.group(0)[:120]
                            f = {"url": t["url"], "param": k0, "test_url": test_url, "evidence": m, "path": t["path"]}
                            self.sql_findings.append(f)
                            self.emit({"type": "sqli_hit", "finding": f})
                            self.log(f"Possible SQL-injection: parameter '{k0}' on {t['path']} leaks a DB error", "warn")
                except Exception:  # noqa: BLE001
                    pass

        await asyncio.gather(*(probe(t) for t in targets.values()))
        self.log(f"Security check complete: {len(self.sql_findings)} parameter(s) leaked a DB error under a quote probe.")

    def _derive_bases(self):
        """From the start URL, work out where the app actually lives so forced-browsing probes the
        right folder - e.g. https://host/etihad_towncg/web/index.php -> web base '/etihad_towncg/web/'
        and project base '/etihad_towncg/'. Returns (web_base, [all bases to probe])."""
        path = urlparse(self.start).path or "/"
        web_base = re.sub(r"/[^/]*\.(php|html?|aspx?|jspx?|asp|cgi)$", "/", path, flags=re.I)
        if not web_base.endswith("/"):
            web_base = web_base.rsplit("/", 1)[0] + "/" if "/" in web_base else "/"
        parent = re.sub(r"/(web|public|public_html|httpdocs|htdocs|www)/$", "/", web_base, flags=re.I)
        project_base = parent if parent != web_base else web_base
        bases = [web_base]
        if parent != web_base:
            bases.append(parent)
        if self.base_path:
            bases.append(self.base_path)
        bases.append("/")
        return web_base, project_base, list(dict.fromkeys(b for b in bases if b))

    def _build_inventory(self, accessible: list[dict], scanned: list[dict]) -> list[dict]:
        """Flat inventory of EVERY folder and file in the project (from the filesystem walk, no HTTP), each
        annotated with access status so the UI can draw the complete tree and flag inaccessible items too."""
        fs = self.fs_result
        if not (fs and fs.get("ok")):
            return []
        acc_by_path = {}
        for a in accessible:
            acc_by_path[a["path"].strip("/")] = a
        probed = {}
        for s in scanned:
            probed[s["path"].strip("/")] = s
        browsable = {a["path"].strip("/") for a in accessible if a.get("kind") == "directory" and a.get("listing")}
        items = []
        for d in fs.get("all_dirs", []):
            rel = d.strip("/")
            a = acc_by_path.get(rel)
            items.append({"path": rel, "kind": "dir",
                          "accessible": True if rel in browsable else (False if rel in probed else None),
                          "severity": a["severity"] if a else None, "group": a["group"] if a else "",
                          "reason": a["reason"] if a else "", "url": a["url"] if a else ""})
        for f in fs.get("all_files", [])[:40000]:
            rel = f.strip("/")
            name = rel.rsplit("/", 1)[-1]
            parent = rel.rsplit("/", 1)[0] if "/" in rel else ""
            a = acc_by_path.get(rel)
            grp, sev = fsaudit.file_type(name)
            if a:
                access = True
            elif rel in probed:
                access = probed[rel].get("accessible", False)
            elif parent in browsable and name.lower() not in ("index.php", "index.html", "index.htm"):
                access = True            # sits in a browsable folder -> downloadable
            else:
                access = None            # not individually tested
            items.append({"path": rel, "kind": "file", "accessible": access,
                          "severity": (a["severity"] if a else (sev if access and sev else None)),
                          "group": (a["group"] if a else grp), "reason": a["reason"] if a else "",
                          "url": a["url"] if a else ""})
        return items

    async def _detect_rewrite(self, origin: str, web_base: str) -> bool:
        """Does the server route every path through the app (Yii/Laravel pretty URLs)? If a clearly bogus
        path still returns 200, directory probing under it is pointless and slow - so we skip it."""
        import uuid as _uuid
        probe = origin.rstrip("/") + "/" + web_base.strip("/") + f"/stressscope_{_uuid.uuid4().hex[:8]}_notreal/"
        try:
            async with httpx.AsyncClient(verify=False, timeout=8, follow_redirects=True) as c:
                r = await c.get(probe)
                return r.status_code == 200
        except Exception:  # noqa: BLE001
            return False

    async def _scan_exposure(self):
        try:
            origin = f"{urlparse(self.start).scheme}://{self.host}"
            web_base, project_base, probe_bases = self._derive_bases()
            bp = (self.base_path or web_base).strip("/") or None
            extra = {}
            web_files: list[str] = []
            self.log(f"Directory scan bases: {', '.join(probe_bases)}")
            project_path = (self.o.get("project_path") or "").strip()
            if project_path:
                self.emit({"type": "status", "phase": "exposure", "msg": f"Scanning local folder {project_path} for risky files"})
                fs = await asyncio.to_thread(fsaudit.walk_project, project_path)
                self.fs_result = fs
                if fs.get("ok"):
                    self.log(f"Local scan: {fs['files_scanned']} files / {fs['dirs_scanned']} folders checked, "
                             f"{fs['findings_total']} risky file(s) found" + (" (scan hit its time/file budget and stopped early)" if fs["truncated"] else ""))
                    extra = fsaudit.candidate_urls(fs)
                    web_files = fsaudit.web_root_files(fs)
                else:
                    self.log(f"Local folder scan failed: {fs.get('error')}", "warn")
            result = await exposure.scan(origin, bp, extra_paths=extra, emit=self.emit, bases=probe_bases)
            have_local = bool(self.fs_result and self.fs_result.get("ok"))
            # live directory-listing crawl of the deployed web/ tree - the way to see inside web/ WITHOUT a
            # local folder. Skipped when we have the local folder (the disk walk already knows every folder).
            if not have_local:
                self.emit({"type": "status", "phase": "exposure", "msg": f"Crawling live directory listings under {web_base}"})
                listing = await exposure.crawl_listings(origin, [web_base, project_base], emit=self.emit, halted=lambda: self.halt_all)
                if listing["accessible"]:
                    self.log(f"Directory-listing crawl: enumerated {listing['checked_files']} file(s) across {listing['checked_dirs']} open folder(s).")
            else:
                listing = {"checked_files": 0, "checked_dirs": 0, "accessible": [], "asset_counts": {}}
            if have_local:
                # Efficient full-project sweep: probe EVERY folder (inside + outside web/) for listing/
                # accessibility, but only the RISKY files individually (config, db, keys, backups, logs,
                # archives, executables...). Benign public assets (images/css/js) are summarised by count,
                # not probed one-by-one - that keeps a 16k-file app fast instead of timing out.
                all_dirs = fsaudit.listable_project_dirs(self.fs_result)   # only folders that could list (fast)
                # Yii pretty-URLs rewrite every web/ path to index.php (runs the app - slow, and no listing ever
                # comes back). Detect that and skip probing folders under web/: their files are still checked
                # directly (served by Apache, fast), and outside-web folders (config, vendor...) are still probed.
                web_prefix = ""
                try:
                    import os as _os
                    if self.fs_result.get("web_root"):
                        web_prefix = _os.path.relpath(self.fs_result["web_root"], self.fs_result["root"]).replace("\\", "/").strip("/")
                        if web_prefix and web_prefix != ".":
                            web_prefix += "/"
                        else:
                            web_prefix = ""
                except Exception:  # noqa: BLE001
                    web_prefix = ""
                rewritten = await self._detect_rewrite(origin, web_base)
                if rewritten and web_prefix:
                    before = len(all_dirs)
                    all_dirs = [d for d in all_dirs if not d.startswith(web_prefix)]
                    self.log(f"URL rewriting detected — skipped {before - len(all_dirs)} inside-web folder probe(s) (rewrites intercept them); files are still checked directly.")
                risky_files, php_samples, asset_summary = [], [], {}
                for f in fsaudit.project_files(self.fs_result):
                    name = f.rsplit("/", 1)[-1]
                    if fsaudit.classify(name):          # genuinely dangerous: sql, bak, key, zip, log, env, exe, db.php...
                        risky_files.append(f)
                    else:
                        grp, _ = fsaudit.file_type(name)
                        asset_summary[grp] = asset_summary.get(grp, 0) + 1
                        if name.lower().rsplit(".", 1)[-1] in ("php", "phtml", "inc") and len(php_samples) < 25:
                            php_samples.append(f)       # sample a few scripts to detect server-wide PHP source disclosure
                probe_files = risky_files + php_samples
                # Don't fetch all 1000s of folders (Apache builds each full listing server-side - slow). Probe a
                # spread-out SAMPLE; if indexing turns out to be on, infer the rest from disk (a folder with no
                # index file is browsable when indexing is enabled). Huge speed-up, same findings.
                if len(all_dirs) > 80:
                    step = max(1, len(all_dirs) // 80)
                    dir_sample = all_dirs[::step][:80]
                else:
                    dir_sample = all_dirs
                self.emit({"type": "status", "phase": "exposure",
                           "msg": f"Deep directory scan: sampling {len(dir_sample)} of {len(all_dirs)} folder(s) and probing {len(probe_files)} risky file(s) under {project_base}"})
                sweep = await exposure.sweep_all(origin, project_base.strip("/") or None, dir_sample, probe_files, emit=self.emit, halted=lambda: self.halt_all)
                sampled_listings = [a for a in sweep["accessible"] if a.get("kind") == "directory" and a.get("listing")]
                if dir_sample and len(sampled_listings) >= max(2, len(dir_sample) * 0.35):
                    probed = {a["path"].strip("/") for a in sweep["accessible"] if a.get("kind") == "directory"}
                    import re as _re
                    sens = _re.compile(r"(config|vendor|runtime|logs?|backup|migrations?|tests?|cache|tmp|temp|uploads?|private|secret|includes?|lib|src|protected|storage|db|sql)", _re.I)
                    base = (project_base.rstrip("/") if project_base != "/" else "")
                    inferred = 0
                    for d in all_dirs:
                        rel = d.strip("/")
                        if rel in probed:
                            continue
                        item = {"url": f"{origin}{base}/{rel}/", "path": rel + "/", "status": 200, "kind": "directory",
                                "listing": True, "group": "Directory Listing", "ftype": "directory",
                                "severity": "critical" if sens.search(rel) else "high",
                                "reason": "Directory indexing is enabled server-wide and this folder has no index file, so it is browsable (inferred from a confirmed sample, not individually fetched)."}
                        sweep["accessible"].append(item)
                        sweep.setdefault("scanned", []).append({"path": rel + "/", "status": 200, "kind": "directory", "accessible": True})
                        inferred += 1
                    sweep["checked_dirs"] += inferred
                    self.log(f"Directory indexing is enabled — inferred {inferred} more browsable folder(s) from disk (sampled {len(dir_sample)}, {len(sampled_listings)} listed).")
                for k, v in asset_summary.items():
                    sweep["asset_counts"][k] = sweep["asset_counts"].get(k, 0) + v
                self.log(f"Directory scan: {sweep['checked_dirs']} folder(s) + {sweep['checked_files']} file(s) probed over HTTP; "
                         f"{len(sweep['accessible'])} directly accessible.")
            else:
                sweep = {"checked_files": 0, "checked_dirs": 0, "accessible": [], "asset_counts": {}}
            # merge the local-folder sweep and the live listing crawl (dedup accessible by url)
            merged_acc = {a["url"]: a for a in listing["accessible"]}
            for a in sweep["accessible"]:
                merged_acc.setdefault(a["url"], a)
            merged_assets = dict(listing["asset_counts"])
            for k, v in sweep["asset_counts"].items():
                merged_assets[k] = merged_assets.get(k, 0) + v
            self.directory_scan = {"checked_files": sweep["checked_files"] + listing["checked_files"],
                                   "checked_dirs": sweep["checked_dirs"] + listing["checked_dirs"],
                                   "accessible": list(merged_acc.values()), "asset_counts": merged_assets,
                                   "scanned": sweep.get("scanned", []) + listing.get("scanned", [])}
            # Complete filesystem inventory (read from DISK, never through index.php): EVERY folder and file,
            # each marked accessible/not/unknown, so the tree shows the whole project and inaccessible items too.
            self.directory_scan["all_items"] = self._build_inventory(self.directory_scan["accessible"], self.directory_scan["scanned"])
            self.web_sweep_checked = self.directory_scan["checked_files"] + self.directory_scan["checked_dirs"]
            existing = {x["url"] for x in result}
            for a in self.directory_scan["accessible"]:
                if a["severity"] in ("critical", "high", "medium") and a["url"] not in existing:
                    result.append({"url": a["url"], "path": a["path"], "status": a["status"], "severity": a["severity"],
                                   "reason": a["reason"], "size": 0, "directory_listing": a.get("listing", False),
                                   "contains_secret_pattern": a.get("secret", False)})
            # screenshots of exposed paths need a browser; skip entirely in directory-only runs (no crawl,
            # the browser may not even be installed) and whenever screenshots are turned off for speed
            if result and self.o.get("crawl_links", True) and self.sp.get("screenshots") != "none" and self.o.get("dir_screenshots", True):
                await self._screenshot_findings(result)
            return result
        except Exception as e:  # noqa: BLE001
            self.log(f"Exposure scan failed: {type(e).__name__}: {e}", "warn")
            return []

    async def _screenshot_findings(self, findings: list[dict]):
        """Live HD screenshots of the worst exposed paths, streamed to the Live Browser View and
        marked with a red outline. A small, separate browser - entirely independent of the crawl."""
        worst = [f for f in findings if f["severity"] in ("critical", "high")][:12]
        if not worst or self.halt_all:
            return
        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True, args=["--disable-gpu", "--mute-audio", "--no-sandbox"])
                ctx = await browser.new_context(viewport={"width": 1920, "height": 1080}, ignore_https_errors=True)
                page = await ctx.new_page()
                await self._start_stream("dir-scan", page)
                self.emit({"type": "status", "phase": "exposure", "msg": f"Capturing {len(worst)} exposed path(s) on the live view"})
                for f in worst:
                    if self.halt_all:
                        break
                    try:
                        await page.goto(f["url"], wait_until="domcontentloaded", timeout=7000)
                        await page.wait_for_timeout(180)
                        try:
                            await page.evaluate("() => { document.documentElement.style.outline = '12px solid #dc2626'; document.documentElement.style.outlineOffset = '-12px'; }")
                        except Exception:  # noqa: BLE001
                            pass
                        name = f"exp_{re.sub(r'[^a-z0-9]+', '_', f['path'].lower())[:50]}_{self._next_id()}.jpg"
                        await page.screenshot(path=os.path.join(self.shots, name), type="jpeg", quality=70, timeout=7000)
                        f["shot"] = name
                        self.emit({"type": "exposure_shot", "finding": f})
                    except Exception:  # noqa: BLE001
                        pass
                await browser.close()
        except Exception as e:  # noqa: BLE001
            self.log(f"Directory screenshot pass failed: {type(e).__name__}: {e}", "warn")

    async def _crawl(self):
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True, args=["--disable-gpu", "--mute-audio", "--no-sandbox"])
            vp = {"width": 1920, "height": 1080}
            self.ctx = await browser.new_context(viewport=vp, ignore_https_errors=True, device_scale_factor=1)
            self.ctx.set_default_timeout(15000)
            await self._seed()
            n = max(1, min(int(self.o["workers"]), self.sp["workers_cap"]))
            workers = [asyncio.create_task(self._worker(i)) for i in range(n)]
            joiner = asyncio.create_task(self.queue.join())
            while not joiner.done():
                if self.halt_all or self.halt_phase:
                    while not self.queue.empty():
                        try:
                            u = self.queue.get_nowait()
                            self.pages[u]["state"] = "skipped"
                            self.queue.task_done()
                        except asyncio.QueueEmpty:
                            break
                await asyncio.sleep(0.25)
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            self.cookies = await self.ctx.cookies()
            self.halt_phase = False
            await browser.close()

    async def _seed_sitemap(self):
        origin = f"{urlparse(self.start).scheme}://{self.host}"
        try:
            async with httpx.AsyncClient(verify=False, timeout=4, follow_redirects=True) as c:
                r = await c.get(origin + "/sitemap.xml")
                if r.status_code == 200 and "<loc" in r.text[:200000]:
                    locs = [e.text.strip() for e in ET.fromstring(r.text).iter() if e.tag.endswith("loc") and e.text][:60]
                    n = 0
                    for l in locs:
                        nu = norm(l)
                        if nu and self.in_scope(nu) and not nu.lower().endswith(SKIP_EXT) and self.add_page(nu, 1, None, "sitemap.xml", "sitemap"):
                            n += 1
                    if n:
                        self.log(f"sitemap.xml: seeded {n} URLs")
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------ worker
    async def _worker(self, wid: int):
        page = await self.ctx.new_page()
        page.on("dialog", lambda d: asyncio.ensure_future(d.dismiss()))
        self.cur[wid] = self._fresh_cur()

        def on_console(m):
            if m.type == "error":
                self.cur[wid]["console"].append(f"{m.text}"[:300])

        def on_failed(r):
            self.cur[wid]["failed"].append({"url": r.url[:200], "status": (r.failure or "failed")[:60]})

        def on_response(r):
            c = self.cur[wid]
            c["reqs"] += 1
            if r.status >= 400 and r.request.resource_type != "document":
                c["failed"].append({"url": r.url[:200], "status": r.status})
            if r.status in (401, 403) and r.request.is_navigation_request():
                c["nav_denied"] = r.status
            if self.base_path and r.request.resource_type in ("document", "xhr", "fetch") and self.in_scope(r.url) \
                    and len(self.all_calls) < 4000:
                self.all_calls.append({"url": r.url.split("#")[0], "method": r.request.method, "status": r.status, "type": r.request.resource_type})

        def on_request(r):
            h = r.headers.get("authorization")
            if h and self.in_scope(r.url) and not self.auth_header:
                self.auth_header = h

        page.on("console", on_console)
        page.on("pageerror", lambda e: self.cur[wid]["errors"].append(str(e)[:300]))
        page.on("requestfailed", on_failed)
        page.on("response", on_response)
        page.on("request", on_request)
        await self._start_stream(wid, page)
        while True:
            try:
                url = await self.queue.get()
            except asyncio.CancelledError:
                break
            try:
                if self.halt_all or self.halt_phase:
                    self.pages[url]["state"] = "skipped"
                else:
                    await self.visit(wid, page, url)
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                rec = self.pages[url]
                rec.update(state="error", error=f"{type(e).__name__}: {str(e)[:160]}")
                self.emit({"type": "page", "page": self.public(rec)})
            finally:
                self.queue.task_done()

    def _fresh_cur(self):
        return {"console": [], "errors": [], "failed": [], "reqs": 0, "nav_denied": 0}

    async def _start_stream(self, wid: int, page):
        gap = 0.22
        last = [0.0]
        try:
            cdp = await self.ctx.new_cdp_session(page)

            async def ack(sid):
                try:
                    await cdp.send("Page.screencastFrameAck", {"sessionId": sid})
                except Exception:  # noqa: BLE001
                    pass

            def on_frame(p):
                asyncio.ensure_future(ack(p["sessionId"]))
                now = time.monotonic()
                if now - last[0] >= gap:
                    last[0] = now
                    self.emit({"type": "frame", "w": wid, "data": p["data"], "url": page.url}, False)

            cdp.on("Page.screencastFrame", on_frame)
            await cdp.send("Page.startScreencast", {"format": "jpeg", "quality": 55, "maxWidth": 1280, "maxHeight": 720, "everyNthFrame": 2})
        except Exception as e:  # noqa: BLE001
            self.log(f"Live stream unavailable for worker {wid}: {e}", "warn")

    async def _settle(self, page, thorough=False):
        idle = self.sp["settle_idle_ms"]
        try:
            await page.wait_for_load_state("load", timeout=9000 if idle else 4000)
        except Exception:  # noqa: BLE001
            pass
        if not self.sp["networkidle"] and not thorough:
            return
        try:
            await page.wait_for_load_state("networkidle", timeout=3500 if thorough else max(idle, 800))
        except Exception:  # noqa: BLE001
            pass

    async def _shot(self, page, name: str, full=False) -> str | None:
        try:
            await page.screenshot(path=os.path.join(self.shots, name), type="jpeg", quality=78, full_page=full, timeout=12000)
            return name
        except Exception:  # noqa: BLE001
            return None

    # ------------------------------------------------------------------ visiting one page
    async def visit(self, wid: int, page, url: str, retried: bool = False):
        rec = self.pages[url]
        rec["state"] = "testing"
        self.emit({"type": "page", "page": self.public(rec)})
        self.emit({"type": "worker", "w": wid, "url": url}, False)
        cur = self.cur[wid] = self._fresh_cur()
        t0 = time.perf_counter()
        try:
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=self.o.get("timeout", 30) * 1000)
            if resp is None:                      # same-document hash navigation
                resp = await page.reload(wait_until="domcontentloaded")
        except Exception as e:  # noqa: BLE001
            msg = str(e)
            if "Download is starting" in msg:
                rec.update(state="skipped", error="File download (not a page)")
            else:
                rec.update(state="error", error=msg.split("\n")[0][:200], load=round((time.perf_counter() - t0) * 1000))
            self.emit({"type": "page", "page": self.public(rec)})
            return
        await self._settle(page, self.o.get("thorough", False))
        wall_ms = round((time.perf_counter() - t0) * 1000)
        final = norm(page.url) or page.url
        status = resp.status if resp else 0
        rec.update(status=status, final_url=final)
        chain, rq = 0, resp.request if resp else None
        while rq is not None and rq.redirected_from is not None:
            chain += 1
            rq = rq.redirected_from
        rec["redirects"] = chain
        is_login_url = bool(LOGIN_URL.search(urlparse(url).path + "?" + urlparse(url).query))
        final_login = bool(LOGIN_URL.search(urlparse(final).path))
        if final != url and not rec.get("alias_of"):
            rec["redirected_to"] = final
        # redirect that landed on an already-tested page -> alias (login redirects are handled separately)
        owner = self.finals.get(final)
        if owner and owner != url and not (final_login and not is_login_url):
            rec.update(state="done", alias_of=owner, category=self.pages[owner]["category"], load=wall_ms)
            self.emit({"type": "page", "page": self.public(rec)})
            return
        ctype = (resp.headers.get("content-type", "") if resp else "").lower()
        if "html" not in ctype and ctype:
            rec.update(state="done", category=rec["category"], load=wall_ms, content_type=ctype.split(";")[0])
            rec["error"] = None
            self.emit({"type": "page", "page": self.public(rec)})
            return
        if self.o.get("expand_menus", True) and self.sp["expand_menus"] and rec["depth"] <= 2:   # persistent chrome is the same on every page - no need past the first couple
            await self._expand_menus(page, final)
        d = await page.evaluate(INSPECT_JS)
        # ---- fill the record
        rec.update(
            ttfb=round(d["ttfb"]), dcl=round(d["dcl"]), load=round(d["load"] or wall_ms), fcp=round(d["fcp"]), lcp=round(d["lcp"]),
            cls=d["cls"], size_kb=round(d["transfer"] / 1024, 1), decoded_kb=round(d["decoded"] / 1024, 1),
            html_kb=round(d["doc_dec"] / 1024, 1), requests=d["nres"], dom_nodes=d["dom"], title=d["title"][:160],
            meta_description=d["desc"][:200], h1_count=d["h1"], canonical=d["canonical"], viewport=d["viewport"], lang=d["lang"],
            images=d["imgs"], img_no_alt=d["img_no_alt"], broken_images=d["img_broken"], forms=d["forms"], inputs=d["inputs"],
            buttons=d["buttons"], buttons_no_name=d["buttons_no_name"], inputs_no_label=d["inputs_no_label"], scripts=d["scripts"],
            mixed_content=d["mixed"], content_type=ctype.split(";")[0], wall_ms=wall_ms,
            compressed=bool(resp and resp.headers.get("content-encoding")) or (d["doc_enc"] and d["doc_enc"] < d["doc_dec"] * 0.92),
        )
        if resp:
            h = resp.headers
            rec["sec_headers"] = {
                "hsts": "strict-transport-security" in h, "csp": "content-security-policy" in h,
                "xfo": "x-frame-options" in h or "frame-ancestors" in h.get("content-security-policy", ""),
                "xcto": "x-content-type-options" in h, "refpol": "referrer-policy" in h,
                "server_disclosure": next((f"{k}: {h[k]}" for k in ("x-powered-by", "server") if k in h and re.search(r"\d", h[k])), ""),
            }
        rec["console_errors"] = list(dict.fromkeys(cur["console"]))[:15]
        rec["page_errors"] = list(dict.fromkeys(cur["errors"]))[:15]
        rec["failed_requests"] = [f for f in {(x["url"], str(x["status"])): x for x in cur["failed"]}.values()][:15]
        # ---- login wall detection
        walled = d["has_pw"] == 1 and not REGISTER_URL.search(urlparse(final).path)
        walled = walled or (status in (401, 403) and d["has_pw"] > 0)
        rec["is_login"] = bool(d["has_pw"] > 0 and (is_login_url or final_login))
        if self.auth_state == "ok" and not (final_login and not is_login_url) and status not in (401, 403):
            walled = False       # authenticated: a password box here is the login page itself or a normal form
        rec["category"] = "Authentication" if rec["is_login"] else analyzer.category_for(final)
        if status in (401, 403) and not walled:
            rec["state"] = "done"
        # screenshot (before login so the login screen is previewed) - gated by speed profile
        shot_mode = self.sp["screenshots"]
        has_issue = (status >= 400) or rec["console_errors"] or rec["page_errors"] or rec.get("is_login")
        if shot_mode == "all" or (shot_mode == "issues" and has_issue):
            rec["shot"] = await self._shot(page, f"p{rec['id']}.jpg", self.o.get("full_page", False))
        if self.o.get("responsive", True) and self.sp["responsive"]:
            vp = page.viewport_size
            try:
                await page.set_viewport_size({"width": 390, "height": 844})
                await page.wait_for_timeout(110)
                rec["mobile_overflow"] = await page.evaluate("document.documentElement.scrollWidth > window.innerWidth + 3")
            except Exception:  # noqa: BLE001
                pass
            finally:
                try:
                    await page.set_viewport_size(vp or {"width": 1920, "height": 1080})
                except Exception:  # noqa: BLE001
                    pass
        if not (final_login and not is_login_url):
            self.finals.setdefault(final, url)
        self.seen.add(final)
        self.seen.add(url)
        if walled and not retried:
            rec["requires_login"] = not is_login_url
            self.emit({"type": "page", "page": self.public(rec)})
            logged = await self._login_wall(wid, page, rec)
            if logged:
                if not is_login_url:
                    # protected target: keep the login screen as its own record, then retest the target
                    if final_login and final != url and final not in self.pages:
                        clone = dict(rec, id=self._next_id(), url=final, final_url=final, is_login=True, requires_login=False,
                                     category="Authentication", state="done", parent=url, children=[], child_text={})
                        clone.pop("redirected_to", None)
                        self.pages[final] = clone
                        self.finals.setdefault(final, final)
                        self.emit({"type": "page", "page": self.public(clone)})
                    rec["state"] = "queued"
                    return await self.visit(wid, page, url, retried=True)
                landing = norm(page.url)           # the login page itself: continue from wherever login landed
                if landing and self.in_scope(landing) and landing not in self.seen:
                    self.add_page(landing, 1, url, "after login", "login")
            elif not is_login_url:
                rec["state"] = "restricted"
                self.emit({"type": "page", "page": self.public(rec)})
                self.emit({"type": "worker", "w": wid, "url": ""}, False)
                return
        elif walled and retried and (final_login or status in (401, 403)):
            rec["state"] = "restricted"
            self.emit({"type": "page", "page": self.public(rec)})
            return
        rec["state"] = "done"
        # ---- discover
        if rec["depth"] < self.o.get("max_depth", 5) and not (walled and self.auth_state != "ok"):
            for l in d["links"]:
                nu = norm(l["href"], page.url)
                if not nu or nu == url:
                    continue
                if not self.in_scope(nu):
                    self.external.setdefault(nu.split("#")[0], set()).add(url)
                    continue
                if nu.split("#")[0].lower().endswith(SKIP_EXT) and "#/" not in nu:
                    continue
                if DANGEROUS.search(urlparse(nu).path + "?" + urlparse(nu).query):
                    self.skipped_links.add(nu)
                    continue
                rec["children"].append(nu)
                rec["child_text"].setdefault(nu, l["text"])
                self.add_page(nu, rec["depth"] + 1, url, l["text"], l["area"])
            rec["children"] = list(dict.fromkeys(rec["children"]))
        rec["links_total"] = len(d["links"])
        if rec["state"] == "done" and not rec.get("is_login") and self.o.get("click_discovery", True) and self.sp["click_discovery"] and rec["depth"] <= 2:
            await self._click_discover(wid, page, rec)
        if rec["state"] == "done" and not rec.get("is_login"):
            await self._scan_action_buttons(page, rec)
        if d.get("forms") and rec["state"] == "done" and not rec.get("is_login") and self.o.get("test_forms", True) and self.sp["forms"]:
            await self._test_forms_on(wid, page, rec)
        self.emit({"type": "page", "page": self.public(rec)})
        self.emit({"type": "worker", "w": wid, "url": ""}, False)

    async def _expand_menus(self, page, expect_url):
        """Click collapsible nav/sidebar toggles (treeview groups, [aria-expanded=false], etc.) so their
        child links become visible and get picked up by link discovery - without following real navigation."""
        try:
            for _ in range(3):
                n = await page.evaluate(EXPAND_MENUS_JS)
                if not n:
                    break
                await page.wait_for_timeout(200)
                if norm(page.url) != expect_url:   # a "toggle" turned out to actually navigate - go back
                    await page.goto(expect_url, wait_until="domcontentloaded", timeout=8000)
                    await self._settle(page)
                    break
        except Exception:  # noqa: BLE001
            pass

    async def _click_discover(self, wid, page, rec):
        """Find nav/sidebar/topbar items with no resolvable URL (JS/Pjax-driven menus) and click
        each one just long enough to see where it goes, then return to the original page. Never
        clicks anything that looks destructive, has a confirm/post action attribute, or sits in a form."""
        try:
            cands = await page.evaluate(NAV_CLICK_JS)
        except Exception:  # noqa: BLE001
            return
        if not cands:
            return
        expect_url = rec["final_url"]
        found = 0
        for c in cands[:25]:
            if self.halt_all or self.halt_phase or len(self.pages) >= self.o["max_pages"]:
                break
            text = c["text"]
            before = page.url
            try:
                await page.get_by_text(text, exact=True).first.click(timeout=2500)
            except Exception:  # noqa: BLE001
                continue
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=2500)
            except Exception:  # noqa: BLE001
                pass
            await page.wait_for_timeout(350)
            after = norm(page.url)
            if after and after != before and self.in_scope(after) and after not in self.seen \
                    and not after.lower().endswith(SKIP_EXT) and not DANGEROUS.search(urlparse(after).path + "?" + urlparse(after).query):
                if self.add_page(after, rec["depth"] + 1, rec["url"], text, "nav"):
                    found += 1
            if page.url != expect_url:
                try:
                    await page.goto(expect_url, wait_until="domcontentloaded", timeout=10000)
                    await self._settle(page)
                except Exception:  # noqa: BLE001
                    return
        if found:
            self.log(f"Click-discovery found {found} additional nav link(s) on {rec['url']}")

    async def _scan_action_buttons(self, page, rec):
        """Purely read-only DOM inspection of Create/Edit/Delete controls - attributes only, never clicked."""
        try:
            found = await page.evaluate(ACTION_BUTTONS_JS)
        except Exception:  # noqa: BLE001
            return
        if not found:
            return
        for f in found:
            f["page"] = rec["url"]
            f["category"] = rec["category"]
        rec["action_buttons"] = found
        if len(self.action_buttons) < 4000:
            self.action_buttons.extend(found)

    async def _test_forms_on(self, wid, page, rec):
        tester = FormTester(page, self.host, self.id, emit=self.emit, submit_forms=self.o.get("submit_forms", False))
        try:
            results = await tester.run(rec["final_url"])
        except Exception as e:  # noqa: BLE001
            results = [{"error": f"{type(e).__name__}: {str(e)[:150]}"}]
        if results:
            rec["form_tests"] = results
            self.log(f"Tested {len(results)} form(s) on {rec['url']}")
            self.emit({"type": "form_test", "url": rec["url"], "results": results})

    def _next_id(self):
        self.seq += 1
        return self.seq

    # ------------------------------------------------------------------ login handling
    async def _login_wall(self, wid, page, rec) -> bool:
        if self.auth_state == "skipped":
            return False
        if self.auth_state == "ok":
            first = not rec.get("authed_retry")
            rec["authed_retry"] = True
            return first
        async with self.auth_lock:
            if self.auth_state == "ok":
                return True
            if self.auth_state == "skipped":
                return False
            return await self._do_login(wid, page, rec)

    async def _do_login(self, wid, page, rec) -> bool:
        self.auth_state = "pending"
        note = None
        attempts = 0
        preset = (self.o.get("username"), self.o.get("password"))
        while attempts < 6 and not self.halt_all:
            fields = await page.evaluate(LOGIN_FIELDS_JS)
            if not fields:
                self.auth_state = "ok"
                return True
            if attempts == 0 and preset[0] and preset[1]:
                values, assigned = {}, False
                for f in fields:
                    if f["secret"]:
                        values[str(f["i"])] = preset[1]
                    elif not assigned:
                        values[str(f["i"])] = preset[0]
                        assigned = True
                self.log("Trying the credentials supplied at start")
            else:
                self.login_seq += 1
                shot = await self._shot(page, f"login_{self.login_seq}.jpg")
                loop = asyncio.get_running_loop()
                self.login_future = loop.create_future()
                self.emit({"type": "login_required", "url": page.url, "shot": shot, "fields": fields, "error": note,
                           "target": rec["url"], "worker": wid})
                res = await self.login_future
                self.login_future = None
                if res.get("skip"):
                    self.auth_state = "skipped"
                    self.emit({"type": "login_result", "ok": False, "skipped": True})
                    self.log("Login skipped - protected pages will be listed but not tested", "warn")
                    return False
                values = res.get("values", {})
            ok, note = await self._submit_login(page, fields, values)
            attempts += 1
            if ok:
                self.auth_state = "ok"
                shot = await self._shot(page, f"after_login_{self.login_seq}.jpg")
                self.emit({"type": "login_result", "ok": True, "shot": shot, "url": page.url})
                self.log("Login successful - continuing inside the authenticated area", "ok")
                return True
            self.log(f"Login failed: {note}", "warn")
        self.auth_state = "skipped"
        self.emit({"type": "login_result", "ok": False, "skipped": True})
        return False

    async def _submit_login(self, page, fields, values):
        before = page.url
        last = None
        for f in fields:
            v = values.get(str(f["i"]))
            if not v:
                continue
            sel = f'[data-st-i="{f["i"]}"]'
            try:
                await page.fill(sel, v, timeout=3000)
                last = sel
            except Exception:  # noqa: BLE001
                pass
        if last is None:
            return False, "No values were entered."
        try:
            await page.press(last, "Enter")
        except Exception:  # noqa: BLE001
            pass
        deadline, clicked, ok = time.time() + 10, False, False
        t0 = time.time()
        while time.time() < deadline:
            await asyncio.sleep(0.35)
            try:
                still = await page.evaluate(HAS_VISIBLE_PW)
            except Exception:  # noqa: BLE001
                continue                         # mid-navigation
            if not still:
                ok = True
                break
            if not clicked and time.time() - t0 > 2.2 and page.url == before:
                clicked = True
                try:
                    await page.click('form button[type=submit], form input[type=submit], form button', timeout=1500)
                except Exception:  # noqa: BLE001
                    pass
        if ok:
            await self._settle(page)
            return True, None
        try:
            err = await page.evaluate(LOGIN_ERR_JS)
        except Exception:  # noqa: BLE001
            err = ""
        return False, err or "The login form is still showing - credentials were probably rejected."

    # ------------------------------------------------------------------ external links, stress, cookies
    async def _check_external(self):
        self.ext_result = {}
        urls = [u for u in self.external if u.startswith("http")][:60]
        if not urls:
            return
        self.emit({"type": "status", "phase": "external", "msg": f"Checking {len(urls)} external links"})
        sem = asyncio.Semaphore(20)

        async def chk(c, u):
            async with sem:
                try:
                    r = await c.head(u)
                    if r.status_code in (405, 403, 501):
                        r = await c.get(u)
                    self.ext_result[u] = {"status": r.status_code, "broken": r.status_code >= 400 and r.status_code not in (401, 403, 429, 999)}
                except Exception as e:  # noqa: BLE001
                    self.ext_result[u] = {"status": type(e).__name__, "broken": isinstance(e, (httpx.ConnectError,)) }

        async with httpx.AsyncClient(verify=False, timeout=8, follow_redirects=True, headers={"User-Agent": "StressScope/1.0"}) as c:
            await asyncio.gather(*(chk(c, u) for u in urls))

    async def _stress(self):
        targets, seen = [], set()
        for p in self.pages.values():
            u = p["url"].split("#")[0]
            if p.get("state") == "done" and not p.get("alias_of") and (p.get("status") or 500) < 400 and u not in seen \
                    and "html" in (p.get("content_type") or "html"):
                seen.add(u)
                targets.append(u)
        targets = targets[:150]
        if not targets:
            self.log("No testable pages for load test", "warn")
            return
        self.emit({"type": "status", "phase": "stress", "msg": f"Load testing {len(targets)} pages with up to {self.o['users']} virtual users"})
        hostname = self.host.split(":")[0]
        ck = "; ".join(f"{c['name']}={c['value']}" for c in self.cookies
                       if hostname == c["domain"].lstrip(".") or hostname.endswith("." + c["domain"].lstrip(".")))
        self.halt_phase = False
        self.stress = await run_load(targets, cookie_header=ck, auth_header=self.auth_header, users=self.o["users"],
                                     duration=self.o["duration"], per_page=self.o["per_page"], emit=self.emit,
                                     halted=lambda: self.halt_all, phase_halted=lambda: self.halt_phase)
        self.halt_phase = False
        self.emit({"type": "stress_done", "stress": {k: v for k, v in self.stress.items() if k != "per_page"}})

    def _cookie_issues(self):
        out = []
        https = urlparse(self.start).scheme == "https"
        for c in self.cookies:
            miss = []
            if https and not c.get("secure"):
                miss.append("Secure")
            if not c.get("httpOnly") and re.search(r"sess|auth|token|sid|jwt", c["name"], re.I):
                miss.append("HttpOnly")
            if c.get("sameSite", "None") in ("None", None) and re.search(r"sess|auth|token|sid|jwt", c["name"], re.I):
                miss.append("SameSite")
            if miss:
                out.append({"name": c["name"], "missing": miss})
        return out
