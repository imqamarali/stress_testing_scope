# StressScope

A web application security, quality and load testing tool. Point it at a site (and
optionally its local project folder) and it crawls every screen, scans the directory
structure, tests forms, and load-tests the app — then produces a live dashboard and
downloadable Excel / Word reports.

## What it does

The scan runs in clear sequential phases:

1. **Directory Testing** — walks the whole project folder (inside and outside `web/`)
   to the deepest level, probes which directories and files are directly reachable over
   HTTP, flags open directory listings, source-code disclosure, exposed configs, DB
   dumps, keys, backups, archives, logs and more, and renders a full collapsible project
   tree with per-folder issue markers and fix suggestions.
2. **Links Testing** — crawls the live app (handling logins), maps every screen and
   groups them by module, follows redirects, inventories Create/Edit/Delete buttons
   (read-only, never clicked), checks security headers, and runs a safe read-only
   error-based SQL-injection probe on parameterised endpoints.
3. **Form Submissions & File Uploading** — validates every form; optionally submits
   forms and benign test uploads only when explicitly allowed (otherwise no database
   changes are made).
4. **Load / Stress test** — hits every discovered page under concurrency and reports
   throughput, latency percentiles and the degradation point.

Other features: three speed modes (Normal / Fast / Ultra Fast browserless crawl),
live HD browser preview, real-time scan feed with progress % and ETA, scan history
with per-scan delete, rescan-flagged, and a report that groups findings by priority.

## Requirements

- Python 3.11+
- Dependencies in `requirements.txt` (FastAPI, uvicorn, Playwright, httpx, openpyxl,
  python-docx, Pillow, matplotlib)
- Playwright Chromium browser

## Install & run

```bash
pip install -r requirements.txt
python -m playwright install chromium
python run.py
```

Then open http://127.0.0.1:8765. On Windows you can also run `start.bat`, which installs
dependencies and launches the app.

## Usage

On the first page, enter the **Project URL** and (for a full directory scan) the
**Project directory** on this machine. Confirm you are authorised to test the target,
click **Start scan**, pick which tracks to run and a speed mode, and watch it work in
real time. Reports download as Excel (`.xlsx`) or Word (`.docx`).

## Authorisation

Only run this against systems you own or are explicitly authorised to test. Crawling is
read-only (GET); logout/delete links are never opened; form submission and file-upload
tests only run when you turn them on.
