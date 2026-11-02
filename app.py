"""FastAPI server: REST + WebSocket live feed for StressScope."""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import sys
import threading
import time
import traceback
import uuid
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

import report as reportgen
from crawler import Scanner, norm

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
os.makedirs(DATA, exist_ok=True)
app = FastAPI(title="StressScope")


class Job:
    def __init__(self, job_id: str, url: str, opts: dict):
        self.id, self.url, self.opts = job_id, url, opts
        self.dir = os.path.join(DATA, job_id)
        self.events: list[dict] = []
        self.subs: set[asyncio.Queue] = set()
        self.last_frames: dict[int, dict] = {}
        self.workers: dict[int, str] = {}
        self.pending_login: dict | None = None
        self.status = {"phase": "starting", "msg": ""}
        self.report: dict | None = None
        self.latest_partial: dict | None = None
        self.scanner: Scanner | None = None
        self.task: asyncio.Task | None = None
        self.created = time.time()

    def emit(self, ev: dict, store: bool = True):
        t = ev["type"]
        if t == "frame":
            self.last_frames[ev["w"]] = ev
        elif t == "worker":
            self.workers[ev["w"]] = ev["url"]
        elif t == "status":
            self.status = {"phase": ev["phase"], "msg": ev.get("msg", "")}
        elif t == "login_required":
            self.pending_login = ev
        elif t == "login_result":
            self.pending_login = None
        elif t == "partial_report":
            self.latest_partial = ev["report"]
        if store and t not in ("page", "frame", "worker"):
            self.events.append(ev)
            if len(self.events) > 4000:
                del self.events[:1000]
        for q in list(self.subs):
            if t in ("frame", "worker") and q.qsize() > 60:
                continue
            q.put_nowait(ev)

    def snapshot(self) -> dict:
        pages = [self.scanner.public(p) for p in self.scanner.pages.values()] if self.scanner else []
        return {"type": "init", "job": {"id": self.id, "url": self.url, "opts": {k: v for k, v in self.opts.items() if k != "password"}},
                "status": self.status, "pages": pages, "events": self.events, "workers": self.workers,
                "pending_login": self.pending_login, "frames": list(self.last_frames.values()),
                "report": self.report, "partial_report": self.latest_partial}


JOBS: dict[str, Job] = {}


def load_job(job_id: str) -> Job | None:
    if job_id in JOBS:
        return JOBS[job_id]
    if not re.fullmatch(r"[a-f0-9]{10}", job_id):
        return None
    f = os.path.join(DATA, job_id, "report.json")
    if os.path.exists(f):
        with open(f, encoding="utf-8") as fh:
            rep = json.load(fh)
        j = Job(job_id, rep["meta"]["url"], {})
        j.report, j.status = rep, {"phase": "done", "msg": "Loaded from history"}
        JOBS[job_id] = j
        return j
    return None


class ScanReq(BaseModel):
    url: str
    authorized: bool = False
    max_pages: int = 0          # 0 = unlimited (capped at a safety ceiling)
    max_depth: int = 12
    workers: int = 6
    stress: bool = True
    users: int = 25
    duration: int = 16
    per_page: int = 10
    username: str = ""
    password: str = ""
    thorough: bool = False
    full_page: bool = False
    responsive: bool = True
    timeout: int = 30
    base_url: str = ""
    test_forms: bool = True
    scan_exposure: bool = True
    expand_menus: bool = True
    click_discovery: bool = True
    submit_forms: bool = False  # actually submit forms / uploads (writes real test data into the database)
    project_path: str = ""
    modes: dict = {}            # {"directory": bool, "links": bool, "forms": bool, "stress": bool} from the scan-mode picker
    speed: str = "normal"       # normal | fast | ultra
    check_sqli: bool = True
    rescan_urls: list = []      # if set, only (re)test these specific URLs/paths - used by "Rescan flagged"


class LoginReq(BaseModel):
    values: dict[str, str] = {}
    skip: bool = False


def clamp(v, lo, hi):
    return max(lo, min(hi, int(v)))


@app.post("/api/scan")
async def start_scan(req: ScanReq):
    if not req.authorized:
        raise HTTPException(400, "You must confirm you own this site or have permission to test it.")
    raw = req.url.strip()
    if not re.match(r"^https?://", raw, re.I):
        raw = "http://" + raw if re.match(r"^(localhost|127\.|\[::1\])", raw) else "https://" + raw
    url = norm(raw)
    if not url or not urlparse(url).hostname:
        raise HTTPException(400, "Enter a valid http(s) URL.")
    if any(j.task and not j.task.done() for j in JOBS.values()):
        raise HTTPException(409, "A scan is already running. Stop it or wait for it to finish.")
    base_url = req.base_url.strip()
    if base_url and not re.match(r"^https?://", base_url, re.I):
        base_url = urlparse(url).scheme + "://" + urlparse(url).netloc + "/" + base_url.lstrip("/")
    opts = req.model_dump()
    max_pages = 20000 if req.max_pages <= 0 else clamp(req.max_pages, 1, 20000)   # 0 = unlimited, capped at a safety ceiling
    # scan-mode picker -> internal flags (default: everything on)
    m = req.modes or {}
    do_dir = m.get("directory", True)
    do_links = m.get("links", True)
    do_forms = m.get("forms", True)
    do_stress = m.get("stress", True)
    opts.update(max_pages=max_pages, max_depth=clamp(req.max_depth, 1, 30), workers=clamp(req.workers, 1, 12),
                users=clamp(req.users, 1, 500), duration=clamp(req.duration, 4, 180), per_page=clamp(req.per_page, 1, 200),
                timeout=clamp(req.timeout, 5, 90), base_url=base_url,
                modes={"directory": do_dir, "links": do_links, "forms": do_forms, "stress": do_stress},
                crawl_links=do_links, scan_exposure=do_dir and req.scan_exposure,
                test_forms=do_links and do_forms and req.test_forms,
                submit_forms=do_links and do_forms and req.submit_forms,
                stress=do_links and do_stress and req.stress,
                speed=req.speed if req.speed in ("normal", "fast", "ultra") else "normal",
                check_sqli=do_links and req.check_sqli,
                rescan_urls=req.rescan_urls or [])
    job_id = uuid.uuid4().hex[:10]
    job = Job(job_id, url, opts)
    job.scanner = Scanner(job_id, url, opts, job.dir, job.emit)
    JOBS[job_id] = job
    job.task = asyncio.create_task(run_job(job))
    return {"id": job_id, "url": url}


async def _live_snapshots(job: Job):
    try:
        while True:
            await asyncio.sleep(3)
            snap = job.scanner.snapshot_report() if job.scanner else None
            if snap:
                job.emit({"type": "partial_report", "report": snap}, store=False)
    except asyncio.CancelledError:
        pass
    except Exception:  # noqa: BLE001
        pass


async def run_job(job: Job):
    ticker = asyncio.create_task(_live_snapshots(job))
    try:
        rep = await job.scanner.run()
        job.report = rep
        with open(os.path.join(job.dir, "report.json"), "w", encoding="utf-8") as fh:
            json.dump(rep, fh, default=str)
        job.emit({"type": "status", "phase": "done", "msg": "Scan complete"})
        job.emit({"type": "report", "report": rep})
    except asyncio.CancelledError:
        raise
    except Exception as e:  # noqa: BLE001
        traceback.print_exc()
        job.emit({"type": "status", "phase": "error", "msg": f"{type(e).__name__}: {e}"})
    finally:
        ticker.cancel()


@app.get("/api/jobs")
async def list_jobs():
    out = []
    for d in os.listdir(DATA):
        f = os.path.join(DATA, d, "report.json")
        if os.path.exists(f):
            try:
                with open(f, encoding="utf-8") as fh:
                    r = json.load(fh)
                out.append({"id": d, "url": r["meta"]["url"], "started": r["meta"]["started"], "overall": r["overall"], "grade": r["grade"]})
            except Exception:  # noqa: BLE001
                pass
    return sorted(out, key=lambda x: -x["started"])[:30]


def _job(job_id) -> Job:
    j = load_job(job_id)
    if not j:
        raise HTTPException(404, "Unknown scan")
    return j


@app.post("/api/jobs/{job_id}/login")
async def submit_login(job_id: str, req: LoginReq):
    j = _job(job_id)
    if not j.scanner:
        raise HTTPException(400, "Not active")
    payload = {"skip": True} if req.skip else {"values": req.values}
    if not j.scanner.provide_login(payload):
        raise HTTPException(409, "No login is pending")
    return {"ok": True}


@app.post("/api/jobs/{job_id}/stop")
async def stop(job_id: str, phase: bool = False):
    j = _job(job_id)
    if j.scanner:
        j.scanner.request_stop(phase_only=phase)
    return {"ok": True}


@app.delete("/api/jobs/{job_id}")
async def delete_job(job_id: str):
    if not re.fullmatch(r"[a-f0-9]{10}", job_id):
        raise HTTPException(400, "Bad id")
    j = JOBS.get(job_id)
    if j:
        if j.scanner:
            j.scanner.request_stop()
        if j.task and not j.task.done():
            j.task.cancel()
        for q in list(j.subs):
            try:
                q.put_nowait({"type": "deleted"})
            except Exception:  # noqa: BLE001
                pass
        JOBS.pop(job_id, None)
    folder = os.path.join(DATA, job_id)
    if os.path.isdir(folder):
        await asyncio.to_thread(shutil.rmtree, folder, True)
    return {"ok": True}


@app.delete("/api/jobs")
async def delete_all_jobs():
    for jid in [d for d in os.listdir(DATA) if re.fullmatch(r"[a-f0-9]{10}", d)]:
        j = JOBS.get(jid)
        if j:
            if j.scanner:
                j.scanner.request_stop()
            if j.task and not j.task.done():
                j.task.cancel()
            JOBS.pop(jid, None)
        await asyncio.to_thread(shutil.rmtree, os.path.join(DATA, jid), True)
    return {"ok": True}


@app.post("/api/restart")
async def restart_app():
    # stop every running scan, then re-exec this process so the whole app restarts fresh
    for j in list(JOBS.values()):
        if j.scanner:
            j.scanner.request_stop()
        if j.task and not j.task.done():
            j.task.cancel()

    def _reexec():
        try:
            os.execv(sys.executable, [sys.executable, os.path.join(ROOT, "run.py")])
        except Exception:  # noqa: BLE001
            os._exit(0)
    threading.Timer(1.0, _reexec).start()
    return {"ok": True}


@app.get("/api/jobs/{job_id}/report.{ext}")
async def download(job_id: str, ext: str):
    j = _job(job_id)
    if not j.report:
        raise HTTPException(409, "Report not ready yet")
    if ext not in ("xlsx", "docx", "json"):
        raise HTTPException(404)
    host = re.sub(r"[^a-z0-9.-]+", "_", urlparse(j.url).netloc.lower())
    name = f"stresstest_{host}_{time.strftime('%Y%m%d_%H%M')}.{ext}"
    path = os.path.join(DATA, j.id, f"report.{ext}")
    shots = os.path.join(DATA, j.id, "shots")
    if ext == "json":
        path = os.path.join(DATA, j.id, "report.json")
    elif not os.path.exists(path):
        fn = reportgen.build_xlsx if ext == "xlsx" else reportgen.build_docx
        await asyncio.to_thread(fn, j.report, shots, path)
    return FileResponse(path, filename=name)


@app.get("/shots/{job_id}/{name}")
async def shot(job_id: str, name: str):
    if not re.fullmatch(r"[a-f0-9]{10}", job_id) or not re.fullmatch(r"[\w.-]+\.jpg", name):
        raise HTTPException(404)
    p = os.path.join(DATA, job_id, "shots", name)
    if not os.path.exists(p):
        raise HTTPException(404)
    return FileResponse(p, media_type="image/jpeg", headers={"Cache-Control": "max-age=3600"})


@app.websocket("/ws/{job_id}")
async def ws(sock: WebSocket, job_id: str):
    await sock.accept()
    j = load_job(job_id)
    if not j:
        await sock.close(code=4404)
        return
    q: asyncio.Queue = asyncio.Queue()
    j.subs.add(q)
    try:
        await sock.send_text(json.dumps(j.snapshot(), default=str))

        async def pump():
            while True:
                ev = await q.get()
                await sock.send_text(json.dumps(ev, default=str))

        pt = asyncio.create_task(pump())
        try:
            while True:
                await sock.receive_text()          # keeps the connection alive; detects disconnect
        finally:
            pt.cancel()
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        pass
    finally:
        j.subs.discard(q)


@app.get("/")
async def index():
    return FileResponse(os.path.join(ROOT, "static", "index.html"))
