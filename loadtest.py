"""Async HTTP load generator: per-page burst + ramped site-wide virtual-user test."""
from __future__ import annotations

import asyncio
import random
import time
from collections import Counter, defaultdict

import httpx

from analyzer import pct

HARD_MAX_USERS = 500
HARD_MAX_SECONDS = 180


class Stats:
    def __init__(self):
        self.lat: list[float] = []
        self.ok = 0
        self.err = 0
        self.bytes = 0
        self.codes: Counter = Counter()
        self.errors: Counter = Counter()

    def add(self, status, ms, size, exc):
        self.lat.append(ms)
        self.bytes += size
        if exc:
            self.err += 1
            self.errors[exc] += 1
            self.codes["ERR"] += 1
        else:
            self.codes[status] += 1
            if status >= 400:
                self.err += 1
                self.errors[f"HTTP {status}"] += 1
            else:
                self.ok += 1

    def summary(self, elapsed):
        n = self.ok + self.err
        return {
            "requests": n, "rps": round(n / elapsed, 1) if elapsed else 0,
            "err_rate": round(100 * self.err / n, 2) if n else 0.0,
            "p50": round(pct(self.lat, 50), 1), "p95": round(pct(self.lat, 95), 1),
            "p99": round(pct(self.lat, 99), 1), "max": round(max(self.lat), 1) if self.lat else 0,
            "avg": round(sum(self.lat) / len(self.lat), 1) if self.lat else 0,
            "mbps": round(self.bytes * 8 / 1e6 / elapsed, 2) if elapsed else 0,
        }


async def run_load(urls, *, cookie_header="", auth_header="", users=25, duration=16, per_page=10,
                   emit=lambda e: None, halted=lambda: False, phase_halted=lambda: False):
    users = max(1, min(int(users), HARD_MAX_USERS))
    duration = max(4, min(int(duration), HARD_MAX_SECONDS))
    per_page = max(1, min(int(per_page), 200))
    headers = {"User-Agent": "StressScope/1.0 (+authorised load test)", "Accept": "text/html,*/*;q=0.8",
               "Accept-Encoding": "gzip, deflate"}
    if cookie_header:
        headers["Cookie"] = cookie_header
    if auth_header:
        headers["Authorization"] = auth_header
    limits = httpx.Limits(max_connections=users + 5, max_keepalive_connections=users + 5)
    per_url: dict[str, Stats] = defaultdict(Stats)
    overall = Stats()
    window: list[tuple[float, float, bool]] = []   # (ts, latency, is_error)
    state = {"active": 0, "phase": "burst", "users": 0}
    codes_429 = 0

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=httpx.Timeout(20.0),
                                 limits=limits, headers=headers) as client:

        async def hit(url, bucket: Stats):
            nonlocal codes_429
            t = time.perf_counter()
            status, size, exc = 0, 0, None
            try:
                r = await client.get(url)
                size = len(r.content)
                status = r.status_code
                if status == 429:
                    codes_429 += 1
            except httpx.TimeoutException:
                exc = "Timeout"
            except httpx.ConnectError:
                exc = "ConnectError"
            except httpx.HTTPError as e:
                exc = type(e).__name__
            except Exception as e:  # noqa: BLE001
                exc = type(e).__name__
            ms = (time.perf_counter() - t) * 1000
            for b in (bucket, per_url[url], overall):
                b.add(status, ms, size, exc)
            window.append((time.time(), ms, bool(exc) or status >= 400))

        async def ticker(stop: asyncio.Event):
            t0 = time.time()
            while not stop.is_set():
                await asyncio.sleep(1)
                now = time.time()
                recent = [w for w in window if now - w[0] <= 1.0]
                del window[:max(0, len(window) - 4000)]
                lat = [w[1] for w in recent]
                emit({"type": "stress_tick", "t": round(now - t0, 1), "rps": len(recent),
                      "p95": round(pct(lat, 95), 1), "avg": round(sum(lat) / len(lat), 1) if lat else 0,
                      "err": sum(1 for w in recent if w[2]), "users": state["users"], "phase": state["phase"]})

        stop_tick = asyncio.Event()
        tick_task = asyncio.create_task(ticker(stop_tick))

        # ---------------- phase 1: per-page burst (every page, `per_page` requests, `users` in flight)
        emit({"type": "stress_phase", "name": "burst", "msg": f"Per-page burst: {len(urls)} pages x {per_page} requests"})
        state["users"] = users
        sem = asyncio.Semaphore(users)
        burst_stats = Stats()

        async def one(u):
            if halted() or phase_halted():
                return
            async with sem:
                await hit(u, burst_stats)

        t0 = time.perf_counter()
        # warm-up so cold-start cost doesn't pollute
        await asyncio.gather(*(hit(u, Stats()) for u in urls[:min(len(urls), 5)]), return_exceptions=True)
        for u in urls:
            per_url[u] = Stats()
        overall = Stats()
        await asyncio.gather(*(one(u) for u in urls for _ in range(per_page)))
        burst_elapsed = time.perf_counter() - t0
        burst = burst_stats.summary(burst_elapsed)

        # ---------------- phase 2: ramped virtual users hitting a random page mix
        steps_users = sorted({max(1, users // 4), max(1, users // 2), max(1, (users * 3) // 4), users})
        step_len = duration / len(steps_users)
        steps = []
        emit({"type": "stress_phase", "name": "ramp", "msg": f"Ramp test: {steps_users} users, {step_len:.0f}s each"})
        baseline_p95 = None
        breaking = None
        for c in steps_users:
            if halted() or phase_halted():
                break
            st = Stats()
            state["users"] = c
            end = time.perf_counter() + step_len

            async def vu():
                while time.perf_counter() < end and not halted() and not phase_halted():
                    await hit(random.choice(urls), st)

            ts = time.perf_counter()
            await asyncio.gather(*(vu() for _ in range(c)))
            s = st.summary(time.perf_counter() - ts)
            s["users"] = c
            steps.append(s)
            if baseline_p95 is None:
                baseline_p95 = max(s["p95"], 50)
            if breaking is None and (s["err_rate"] > 5 or s["p95"] > max(3 * baseline_p95, 2000)):
                breaking = c
        stop_tick.set()
        await tick_task

    per_page_out = {}
    for u, st in per_url.items():
        if not st.lat:
            continue
        s = st.summary(max(1e-6, burst_elapsed + duration))
        per_page_out[u] = {"url": u, **{k: s[k] for k in ("requests", "err_rate", "p50", "p95", "p99", "max", "avg")},
                           "codes": {str(k): v for k, v in st.codes.items()}}
    elapsed = burst_elapsed + sum(step_len for _ in steps)
    ov = overall.summary(elapsed)
    if steps:                       # headline numbers = the peak step (what the site sustained at full load)
        peak = steps[-1]
        ov.update({"rps": peak["rps"], "p50": peak["p50"], "p95": peak["p95"], "p99": peak["p99"], "max": max(s["max"] for s in steps)})
    return {
        "ran": True, "users": users, "duration": duration, "per_page_requests": per_page,
        "overall": ov, "burst": burst, "steps": steps, "breaking_users": breaking,
        "per_page": per_page_out, "errors": dict(overall.errors), "codes": {str(k): v for k, v in overall.codes.items()},
        "rate_limited": codes_429, "total_requests": overall.ok + overall.err,
    }
