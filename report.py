"""Excel and Word report generation."""
from __future__ import annotations

import datetime as dt
import io
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from docx import Document  # noqa: E402
from docx.enum.table import WD_TABLE_ALIGNMENT  # noqa: E402
from docx.enum.text import WD_ALIGN_PARAGRAPH  # noqa: E402
from docx.oxml import OxmlElement  # noqa: E402
from docx.oxml.ns import qn  # noqa: E402
from docx.shared import Inches, Pt, RGBColor  # noqa: E402
from openpyxl import Workbook  # noqa: E402
from openpyxl.chart import BarChart, LineChart, Reference  # noqa: E402
from openpyxl.drawing.image import Image as XLImage  # noqa: E402
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side  # noqa: E402
from openpyxl.utils import get_column_letter  # noqa: E402
from PIL import Image  # noqa: E402

SEV_COLOR = {"critical": "B91C1C", "high": "EA580C", "medium": "CA8A04", "low": "2563EB", "info": "64748B"}
NAVY, TEAL, LIGHT = "0F172A", "0D9488", "F1F5F9"
THIN = Side(style="thin", color="CBD5E1")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)


def _score_color(s):
    return "16A34A" if s >= 85 else "CA8A04" if s >= 65 else "DC2626"


def _when(rep):
    return dt.datetime.fromtimestamp(rep["meta"]["started"]).strftime("%d %b %Y %H:%M")


def _thumb(path, width=520):
    try:
        im = Image.open(path).convert("RGB")
        h = int(im.height * width / im.width)
        im = im.resize((width, h))
        buf = io.BytesIO()
        im.save(buf, "JPEG", quality=80)
        buf.seek(0)
        return buf
    except Exception:  # noqa: BLE001
        return None


# =============================================================================== EXCEL
def build_xlsx(rep: dict, shots_dir: str, out_path: str):
    wb = Workbook()
    hdr_font = Font(bold=True, color="FFFFFF", name="Calibri")
    hdr_fill = PatternFill("solid", fgColor=NAVY)

    def table(ws, row, headers, rows, widths=None, wrap_cols=()):
        for j, h in enumerate(headers, 1):
            c = ws.cell(row, j, h)
            c.font, c.fill, c.border = hdr_font, hdr_fill, BORDER
            c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        for i, r in enumerate(rows, row + 1):
            for j, v in enumerate(r, 1):
                c = ws.cell(i, j, v)
                c.border = BORDER
                c.alignment = Alignment(vertical="top", wrap_text=(j in wrap_cols))
                if (i - row) % 2 == 0:
                    c.fill = PatternFill("solid", fgColor=LIGHT)
        if widths:
            for j, w in enumerate(widths, 1):
                ws.column_dimensions[get_column_letter(j)].width = w
        ws.freeze_panes = ws.cell(row + 1, 1)
        return row + len(rows) + 1

    # ---------------- Summary
    ws = wb.active
    ws.title = "Summary"
    ws.sheet_view.showGridLines = False
    ws["A1"] = "Website Stress & Quality Report"
    ws["A1"].font = Font(size=20, bold=True, color=NAVY)
    ws["A2"] = f"{rep['meta']['url']}   |   {_when(rep)}   |   scan time {rep['meta']['duration_s']} s   |   {'authenticated' if rep['meta']['authenticated'] else 'public access'}"
    ws["A2"].font = Font(color="64748B")
    ws["A4"] = "OVERALL SCORE"
    ws["A4"].font = Font(bold=True, color="64748B")
    ws["A5"] = rep["overall"]
    ws["A5"].font = Font(size=36, bold=True, color=_score_color(rep["overall"]))
    ws["B5"] = f"Grade {rep['grade']}  -  {rep['verdict']}"
    ws["B5"].font = Font(size=16, bold=True, color=NAVY)
    ws["B5"].alignment = Alignment(vertical="center")
    ws.row_dimensions[5].height = 46
    r = 7
    ws.cell(r, 1, "Scores").font = Font(bold=True, size=13)
    r = table(ws, r + 1, ["Area", "Score"], [[k, v] for k, v in rep["scores"].items()], [26, 18, 18, 18, 18, 18, 18])
    score_rows = (r - len(rep["scores"]), r - 1)
    for rr in range(score_rows[0], score_rows[1] + 1):
        ws.cell(rr, 2).font = Font(bold=True, color=_score_color(ws.cell(rr, 2).value))
    k = rep["kpis"]
    ws.cell(7, 4, "Key metrics").font = Font(bold=True, size=13)
    kp = [("URLs discovered", k["urls"]), ("Pages tested", k["tested"]), ("Categories", k["categories"]), ("Avg load (ms)", k["avg_load"]),
          ("p95 load (ms)", k["p95_load"]), ("Error pages", k["errors"]), ("Broken links", k["broken_links"]),
          ("Console errors", k["console_errors"]), ("Login-protected (untested)", k["restricted"]), ("Findings", k["findings"]),
          ("Total transfer (MB)", k["total_mb"]), ("Forms tested", k.get("forms_tested", 0)), ("Upload tests run", k.get("uploads_tested", 0)),
          ("Critical exposed paths", k.get("exposure_critical", 0))]
    for j, (a, b) in enumerate(kp):
        ws.cell(8 + j, 4, a).border = BORDER
        c = ws.cell(8 + j, 5, b)
        c.border = BORDER
        c.font = Font(bold=True)
    r = max(r, 8 + len(kp)) + 1
    ws.cell(r, 1, "Executive summary").font = Font(bold=True, size=13)
    for s in rep["summary"]:
        r += 1
        ws.cell(r, 1, s).alignment = Alignment(wrap_text=True, vertical="top")
        ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=8)
        ws.row_dimensions[r].height = 34
    r += 2
    ch = BarChart()
    ch.type, ch.title, ch.style = "bar", "Scores by area", 10
    ch.add_data(Reference(ws, min_col=2, min_row=score_rows[0] - 1, max_row=score_rows[1]), titles_from_data=True)
    ch.set_categories(Reference(ws, min_col=1, min_row=score_rows[0], max_row=score_rows[1]))
    ch.y_axis.scaling.min, ch.y_axis.scaling.max = 0, 100
    ch.legend = None
    ch.height, ch.width = 7.5, 14
    ws.add_chart(ch, f"A{r}")

    # ---------------- Findings
    ws = wb.create_sheet("Findings")
    rows = [[i + 1, f["severity"].upper(), f["area"], f["title"], f["detail"], f["fix"], f["count"], "\n".join(f["pages"][:6])]
            for i, f in enumerate(rep["insights"])]
    table(ws, 1, ["#", "Severity", "Area", "Finding", "Details", "Recommended fix", "Affected", "Example URLs"], rows,
          [5, 11, 15, 46, 52, 52, 10, 50], wrap_cols=(4, 5, 6, 8))
    for i, f in enumerate(rep["insights"], 2):
        c = ws.cell(i, 2)
        c.fill = PatternFill("solid", fgColor=SEV_COLOR[f["severity"]])
        c.font = Font(bold=True, color="FFFFFF")
        c.alignment = Alignment(horizontal="center", vertical="top")
    ws.auto_filter.ref = ws.dimensions

    # ---------------- Categories
    ws = wb.create_sheet("Categories")
    rows = [[c["name"], c["status"], c["pages"], c["tested"], c["restricted"], c["errors"], c["console_errors"], c["avg_load"], c["max_load"],
             c["avg_size_kb"], c["avg_requests"], c["load_p95"] or ""] for c in rep["categories"]]
    end = table(ws, 1, ["Category", "Status", "Pages", "Tested", "Login-gated", "Error pages", "Console errors", "Avg load (ms)", "Max load (ms)",
                        "Avg size (KB)", "Avg requests", "p95 under load (ms)"], rows, [24, 12, 9, 9, 12, 12, 14, 14, 14, 14, 13, 18])
    fills = {"Healthy": "DCFCE7", "Warning": "FEF9C3", "Critical": "FEE2E2"}
    for i, c in enumerate(rep["categories"], 2):
        ws.cell(i, 2).fill = PatternFill("solid", fgColor=fills[c["status"]])
    if rows:
        bc = BarChart()
        bc.title, bc.style, bc.height, bc.width = "Average load time by category (ms)", 10, 8, 18
        bc.add_data(Reference(ws, min_col=8, min_row=1, max_row=end - 1 + 0), titles_from_data=True)
        bc.set_categories(Reference(ws, min_col=1, min_row=2, max_row=end - 1))
        bc.legend = None
        ws.add_chart(bc, f"A{end + 3}")

    # ---------------- Pages
    ws = wb.create_sheet("Pages")
    cols = ["Category", "URL", "Final URL", "Discovered from", "Link text", "Depth", "State", "HTTP", "Title", "TTFB ms", "DOM ready ms", "Load ms", "FCP ms",
            "LCP ms", "CLS", "Size KB", "Requests", "DOM nodes", "Console errors", "Failed requests", "Broken imgs", "Imgs w/o alt", "Mobile overflow",
            "Login required", "Compressed", "HSTS", "CSP", "X-Frame", "X-Content-Type", "Referrer-Policy", "Error"]
    rows = []
    for p in sorted(rep["pages"], key=lambda p: (p["category"], p["url"])):
        sh = p.get("sec_headers") or {}
        yn = lambda v: "" if v is None else ("Yes" if v else "No")  # noqa: E731
        rows.append([p["category"], p["url"], p.get("final_url") if p.get("final_url") != p["url"] else "", p.get("parent") or "", p.get("link_text") or "",
                     p.get("depth"), p["state"] + (f" (= {p['alias_of']})" if p.get("alias_of") else ""), p.get("status"), p.get("title"), p.get("ttfb"),
                     p.get("dcl"), p.get("load"), p.get("fcp"), p.get("lcp"), p.get("cls"), p.get("size_kb"), p.get("requests"), p.get("dom_nodes"),
                     len(p.get("console_errors", [])) + len(p.get("page_errors", [])), len(p.get("failed_requests", [])), p.get("broken_images"),
                     p.get("img_no_alt"), yn(p.get("mobile_overflow")), "Yes" if p.get("requires_login") else "", yn(p.get("compressed")),
                     yn(sh.get("hsts")) if sh else "", yn(sh.get("csp")) if sh else "", yn(sh.get("xfo")) if sh else "", yn(sh.get("xcto")) if sh else "",
                     yn(sh.get("refpol")) if sh else "", p.get("error") or ""])
    table(ws, 1, cols, rows, [20, 48, 36, 36, 22, 7, 14, 7, 34] + [10] * 22)
    load_i = cols.index("Load ms") + 1
    for i in range(2, len(rows) + 2):
        c = ws.cell(i, load_i)
        v = c.value or 0
        if v > 4000:
            c.fill = PatternFill("solid", fgColor="FECACA")
        elif v > 2500:
            c.fill = PatternFill("solid", fgColor="FEF08A")
        elif v:
            c.fill = PatternFill("solid", fgColor="BBF7D0")
        h = ws.cell(i, 8)
        if (h.value or 0) >= 400:
            h.fill = PatternFill("solid", fgColor="FECACA")
    ws.auto_filter.ref = ws.dimensions

    # ---------------- Broken links
    ws = wb.create_sheet("Broken Links")
    table(ws, 1, ["Source page", "Broken target", "Status", "Link text"], [[b["source"], b["target"], b["status"], b["text"]] for b in rep["broken_links"]] or [["No broken links found", "", "", ""]],
          [60, 60, 14, 30])

    # ---------------- Forms & validation
    ws = wb.create_sheet("Forms")
    rows = []
    for f in rep.get("forms", []):
        if "error" in f and "cases" not in f:
            rows.append([f["page"], f.get("form_action"), f.get("method"), "", "", "could not be tested", "", f["error"]])
            continue
        sub = f.get("submission") or {}
        sub_txt = "not submitted" if sub.get("skipped") or not sub.get("submitted") else sub.get("outcome", "unclear")
        if not f.get("cases"):
            rows.append([f["page"], f["form_action"], f["method"], f["field_count"], "; ".join(f.get("skipped_sensitive") or []), "-", "-", sub_txt])
        for c in f["cases"]:
            rows.append([f["page"], f["form_action"], f["method"], f["field_count"], "; ".join(f.get("skipped_sensitive") or []),
                        c["case"], "PASS" if c["pass"] else "CHECK", f"{c['result']} - {c['detail']}" + (f" | submission: {sub_txt}" if c is f["cases"][-1] else "")])
    table(ws, 1, ["Page", "Form action", "Method", "Fields", "Sensitive fields skipped", "Validation case", "Status", "Detail"], rows,
          [40, 42, 9, 8, 26, 26, 9, 60], wrap_cols=(8,))
    for i, r in enumerate(rows, 2):
        if r[6] == "CHECK":
            ws.cell(i, 7).fill = PatternFill("solid", fgColor="FEF08A")
        elif r[6] == "PASS":
            ws.cell(i, 7).fill = PatternFill("solid", fgColor="BBF7D0")

    # ---------------- Upload security
    ws = wb.create_sheet("Upload Security")
    def exec_txt(u):
        if u.get("executed") is True:
            return "YES - SERVER EXECUTED IT"
        if u.get("content_type_risk"):
            return "renders as active content"
        return "no" if u.get("executed") is False else "n/a"
    rows = [[u["page"], u.get("form_action"), u["field"], u["case"], u["filename"], u["status"], exec_txt(u), u["expect"], u["note"]]
            for u in rep.get("uploads", [])]
    table(ws, 1, ["Page", "Form action", "Field", "Test case", "Filename", "Server response", "Executed / renderable?", "Expected", "What this tests"],
          rows or [["No file upload fields were found", "", "", "", "", "", "", "", ""]], [34, 34, 16, 20, 26, 14, 20, 18, 52], wrap_cols=(9,))
    for i, u_ in enumerate(rep.get("uploads", []), 2):
        if u_.get("executed") is True:
            ws.cell(i, 6).fill = ws.cell(i, 7).fill = PatternFill("solid", fgColor="B91C1C")
            ws.cell(i, 7).font = Font(color="FFFFFF", bold=True)
        elif u_.get("content_type_risk"):
            ws.cell(i, 7).fill = PatternFill("solid", fgColor="FDBA74")
        elif u_["status"] == "accepted" and u_["case"] != "valid" and u_["expect"] in ("rejected", "rejected_or_flagged", "rejected_or_sanitised"):
            ws.cell(i, 6).fill = PatternFill("solid", fgColor="FEF08A")
        elif u_["status"] in ("rejected",) or (u_["case"] == "valid" and u_["status"] == "accepted"):
            ws.cell(i, 6).fill = PatternFill("solid", fgColor="BBF7D0")

    # ---------------- SQL injection
    sqlf = rep.get("sql_findings") or []
    if sqlf:
        ws = wb.create_sheet("SQL Injection")
        ws["A1"] = "Error-based SQL-injection probe (safe, read-only single-quote test)"
        ws["A1"].font = Font(bold=True, size=13)
        rows = [["CRITICAL", s["param"], s["url"], s["evidence"], s["test_url"]] for s in sqlf]
        table(ws, 3, ["Severity", "Parameter", "Endpoint", "DB error evidence", "Probe URL"], rows, [11, 20, 50, 44, 50], wrap_cols=(4,))
        for i in range(len(sqlf)):
            ws.cell(4 + i, 1).fill = PatternFill("solid", fgColor=SEV_COLOR["critical"])
            ws.cell(4 + i, 1).font = Font(bold=True, color="FFFFFF")

    # ---------------- Directory scan (grouped, directly-accessible dirs & files)
    dscan = rep.get("directory_scan") or {}
    if dscan.get("groups"):
        ws = wb.create_sheet("Directory Scan")
        ws["A1"] = f"Deep directory scan - {dscan.get('checked_dirs',0)} folder(s) and {dscan.get('checked_files',0)} file(s) probed directly over HTTP"
        ws["A1"].font = Font(bold=True, size=13)
        assets = ", ".join(f"{v} {k.lower()}" for k, v in (dscan.get("asset_counts") or {}).items())
        if assets:
            ws["A2"] = f"Expected public assets reachable (not flagged): {assets}"
            ws["A2"].font = Font(italic=True, color="64748B")
        row = 4
        for g in dscan["groups"]:
            ws.cell(row, 1, f"{g['group']}  ({g['count']})").font = Font(bold=True, size=12, color=NAVY)
            row += 1
            grows = [[it["severity"].upper(), it["path"], it["url"], it["status"], it["reason"]] for it in g["items"]]
            row = table(ws, row, ["Severity", "Path", "Full URL", "HTTP", "Why it matters"], grows, [11, 40, 50, 7, 50], wrap_cols=(5,))
            for i, it in enumerate(g["items"], row - len(grows)):
                ws.cell(i, 1).fill = PatternFill("solid", fgColor=SEV_COLOR.get(it["severity"], "64748B"))
                ws.cell(i, 1).font = Font(bold=True, color="FFFFFF")
            row += 1

    # ---------------- Exposure scan
    ws = wb.create_sheet("Exposure Scan")
    exp = rep.get("exposure", {})
    sweep_n = (rep.get("local_files") or {}).get("web_sweep_checked", 0)
    ws["A1"] = "Unauthenticated exposure scan - paths checked without any login session" + (f"  |  {sweep_n} web-root file(s) individually checked over HTTP" if sweep_n else "")
    ws["A1"].font = Font(bold=True, size=13)
    rows = [[e["severity"].upper(), e["path"], e["url"], e["status"], e["reason"], e["size"], "Yes" if e["directory_listing"] else "", "Yes" if e["contains_secret_pattern"] else ""]
            for e in exp.get("findings", [])]
    table(ws, 3, ["Severity", "Path", "Full URL", "HTTP", "Why it matters", "Bytes", "Directory listing", "Secret pattern found"],
          rows or [["", "No publicly exposed sensitive paths were found", "", "", "", "", "", ""]], [11, 30, 46, 7, 46, 9, 15, 15], wrap_cols=(5,))
    for i, e in enumerate(exp.get("findings", []), 4):
        ws.cell(i, 1).fill = PatternFill("solid", fgColor=SEV_COLOR[e["severity"]])
        ws.cell(i, 1).font = Font(bold=True, color="FFFFFF")

    lf = rep.get("local_files", {})
    fsres = lf.get("result")
    if fsres:
        r0 = ws.max_row + 3
        ws.cell(r0, 1, "Local project folder scan (filesystem, not HTTP)").font = Font(bold=True, size=13)
        if fsres.get("ok"):
            ws.cell(r0 + 1, 1, f"Root: {fsres['root']}" + (f"  |  detected web root: {fsres['web_root']}" if fsres.get("web_root") else "  |  no web/ subfolder detected - the project root itself is likely the served folder")).font = Font(italic=True)
            ws.cell(r0 + 2, 1, f"{fsres['files_scanned']} files / {fsres['dirs_scanned']} folders scanned" + (" (stopped early - time/file budget reached)" if fsres.get("truncated") else ""))
            rows = [[f["severity"].upper(), f["rel_root"], f["category"], "Yes" if f["in_web_root"] else "", f["size"]] for f in lf.get("findings", [])]
            table(ws, r0 + 4, ["Severity", "Path (from project root)", "Category", "Inside public web root?", "Bytes"],
                  rows or [["", "No risky files found on disk", "", "", ""]], [11, 55, 18, 18, 10])
            for i, f in enumerate(lf.get("findings", []), r0 + 5):
                ws.cell(i, 1).fill = PatternFill("solid", fgColor=SEV_COLOR[f["severity"]])
                ws.cell(i, 1).font = Font(bold=True, color="FFFFFF")
                if f["in_web_root"]:
                    ws.cell(i, 4).fill = PatternFill("solid", fgColor="FECACA")
        else:
            ws.cell(r0 + 1, 1, f"Could not scan: {fsres.get('error')}")

    # ---------------- Action buttons (Create / Edit / Delete) - read-only inventory, never clicked
    ab = rep.get("action_buttons", [])
    if ab:
        ws = wb.create_sheet("Action Buttons")
        ws["A1"] = "Create / Edit / Delete controls - inventoried from each control's HTML attributes only. Nothing here was clicked."
        ws["A1"].font = Font(bold=True, size=12)
        rows = [[a["page"], a["category"], a["type"].upper(), a["label"], a["href"], a["method"] or "", "Yes" if a["has_confirm"] else "No",
                 a["confirm_message"], "Yes" if a["has_onclick"] else ""] for a in ab]
        table(ws, 3, ["Page", "Category", "Type", "Label", "Href", "data-method", "Has confirm?", "Confirm message", "Has onclick?"],
              rows, [40, 18, 9, 22, 40, 11, 11, 44, 11], wrap_cols=(8,))
        for i, a in enumerate(ab, 4):
            if a["type"] == "delete" and not a["has_confirm"] and not a["has_onclick"]:
                ws.cell(i, 7).fill = PatternFill("solid", fgColor="FECACA")
            elif a["type"] == "delete" and a["has_confirm"]:
                ws.cell(i, 7).fill = PatternFill("solid", fgColor="BBF7D0")

    # ---------------- Scope / base URL
    scope = rep.get("scope") or {}
    if scope.get("base_url"):
        ws = wb.create_sheet("Base URL Scope")
        ws["A1"] = f"Configured base URL: {scope['base_url']}"
        ws["A1"].font = Font(bold=True, size=13)
        ws["A2"] = f"{scope.get('total_calls', 0)} GET/POST call(s) observed; {len(scope.get('out_of_base', []))} fell outside this base URL."
        table(ws, 4, ["URL", "Method", "Status", "Type"], [[c["url"], c["method"], c["status"], c["type"]] for c in scope.get("out_of_base", [])] or
              [["None - every call stayed within the configured base URL", "", "", ""]], [70, 10, 10, 12])

    # ---------------- Load test
    ws = wb.create_sheet("Load Test")
    st = rep.get("stress")
    if st and st.get("ran"):
        ov = st["overall"]
        ws["A1"] = f"Load test - up to {st['users']} virtual users, {st['per_page_requests']} burst requests/page, {st['total_requests']} total requests"
        ws["A1"].font = Font(bold=True, size=13)
        r = table(ws, 3, ["Metric", "Value"], [["Peak throughput (req/s)", ov["rps"]], ["p50 latency (ms)", ov["p50"]], ["p95 latency (ms)", ov["p95"]],
                                               ["p99 latency (ms)", ov["p99"]], ["Max latency (ms)", ov["max"]], ["Error rate (%)", ov["err_rate"]],
                                               ["Degradation begins at (users)", st["breaking_users"] or "not reached"], ["Rate-limited (429)", st["rate_limited"]]],
                  [34, 18, 14, 14, 14, 14, 14, 14])
        ws.cell(r + 1, 1, "Ramp test").font = Font(bold=True, size=12)
        hdr_row = r + 2
        r2 = table(ws, hdr_row, ["Virtual users", "Requests", "Req/s", "p50 ms", "p95 ms", "p99 ms", "Error %", "Mbit/s"],
                   [[s["users"], s["requests"], s["rps"], s["p50"], s["p95"], s["p99"], s["err_rate"], s["mbps"]] for s in st["steps"]])
        if len(st["steps"]) > 1:
            lc = LineChart()
            lc.title, lc.height, lc.width = "Latency vs concurrent users", 8, 16
            lc.add_data(Reference(ws, min_col=4, max_col=6, min_row=hdr_row, max_row=r2 - 1), titles_from_data=True)
            lc.set_categories(Reference(ws, min_col=1, min_row=hdr_row + 1, max_row=r2 - 1))
            ws.add_chart(lc, f"J{hdr_row}")
        r3 = r2 + 3
        ws.cell(r3 - 1, 1, "Per-page results (burst + ramp)").font = Font(bold=True, size=12)
        pp = sorted(st["per_page"].values(), key=lambda x: -x["p95"])
        table(ws, r3, ["URL", "Requests", "Avg ms", "p50 ms", "p95 ms", "p99 ms", "Max ms", "Error %"],
              [[x["url"], x["requests"], x["avg"], x["p50"], x["p95"], x["p99"], x["max"], x["err_rate"]] for x in pp])
        ws.column_dimensions["A"].width = 60
        ws.freeze_panes = None
    else:
        ws["A1"] = "Load test was not run (disabled or crawl stopped early)."

    # ---------------- Screenshots
    ws = wb.create_sheet("Screenshots")
    ws.column_dimensions["A"].width = 26
    ws.column_dimensions["B"].width = 80
    ws["A1"], ws["B1"] = "Category / URL", "Preview (1920x1080 capture)"
    for c in (ws["A1"], ws["B1"]):
        c.font, c.fill = hdr_font, hdr_fill
    row, n = 2, 0
    for p in sorted(rep["pages"], key=lambda p: (p["category"], p["url"])):
        if not p.get("shot") or p.get("alias_of") or n >= 60:
            continue
        buf = _thumb(os.path.join(shots_dir, p["shot"]), 560)
        if not buf:
            continue
        img = XLImage(buf)
        img.width, img.height = 560, int(560 * 9 / 16)
        ws.add_image(img, f"B{row}")
        ws.cell(row, 1, f"{p['category']}\n{p['url']}\nHTTP {p.get('status')} | {p.get('load')} ms").alignment = Alignment(wrap_text=True, vertical="top")
        ws.row_dimensions[row].height = 240
        row += 1
        n += 1
    wb.save(out_path)


# =============================================================================== WORD
def _shade(cell, hexcolor):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hexcolor)
    tcPr.append(shd)


def _chart_png(fn):
    fig = plt.figure(figsize=(7.2, 3.2), dpi=150)
    fn(fig.add_subplot(111))
    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png")
    plt.close(fig)
    buf.seek(0)
    return buf


def build_docx(rep: dict, shots_dir: str, out_path: str):
    d = Document()
    sec = d.sections[0]
    sec.left_margin = sec.right_margin = Inches(0.8)
    sec.top_margin = sec.bottom_margin = Inches(0.7)
    st = d.styles["Normal"]
    st.font.name, st.font.size = "Calibri", Pt(10.5)

    def h(text, lvl=1):
        p = d.add_heading(text, lvl)
        for r in p.runs:
            r.font.color.rgb = RGBColor.from_string(NAVY)
        return p

    def tbl(headers, rows, widths=None, sev_col=None, font=9):
        t = d.add_table(rows=1, cols=len(headers))
        t.style, t.alignment = "Table Grid", WD_TABLE_ALIGNMENT.CENTER
        for i, x in enumerate(headers):
            c = t.rows[0].cells[i]
            c.text = ""
            run = c.paragraphs[0].add_run(x)
            run.bold, run.font.size, run.font.color.rgb = True, Pt(font), RGBColor(255, 255, 255)
            _shade(c, NAVY)
        for r in rows:
            cells = t.add_row().cells
            for i, v in enumerate(r):
                cells[i].text = ""
                run = cells[i].paragraphs[0].add_run(str(v) if v is not None else "")
                run.font.size = Pt(font)
                if sev_col is not None and i == sev_col and str(v).lower() in SEV_COLOR:
                    _shade(cells[i], SEV_COLOR[str(v).lower()])
                    run.font.color.rgb, run.bold = RGBColor(255, 255, 255), True
        if widths:
            for row in t.rows:
                for i, w in enumerate(widths):
                    row.cells[i].width = Inches(w)
        d.add_paragraph()
        return t

    # ---- cover
    t = d.add_paragraph()
    t.alignment = WD_ALIGN_PARAGRAPH.LEFT
    r = t.add_run("Website Stress & Quality Report")
    r.bold, r.font.size, r.font.color.rgb = True, Pt(26), RGBColor.from_string(NAVY)
    p = d.add_paragraph()
    p.add_run(rep["meta"]["url"]).font.size = Pt(13)
    d.add_paragraph(f"Generated {_when(rep)}  |  scan duration {rep['meta']['duration_s']} s  |  "
                    f"{'authenticated session' if rep['meta']['authenticated'] else 'public access only'}")
    big = d.add_paragraph()
    rr = big.add_run(f"{rep['overall']}/100  ")
    rr.bold, rr.font.size, rr.font.color.rgb = True, Pt(40), RGBColor.from_string(_score_color(rep["overall"]))
    rr2 = big.add_run(f"Grade {rep['grade']}  -  {rep['verdict']}")
    rr2.bold, rr2.font.size = True, Pt(16)

    h("Executive summary", 1)
    for s in rep["summary"]:
        d.add_paragraph(s, style="List Bullet")
    k = rep["kpis"]
    tbl(["URLs", "Tested", "Categories", "Avg load", "p95 load", "Error pages", "Broken links", "Findings"],
        [[k["urls"], k["tested"], k["categories"], f"{k['avg_load']:.0f} ms", f"{k['p95_load']:.0f} ms", k["errors"], k["broken_links"], k["findings"]]])
    tbl(["Forms tested", "Upload tests", "Critical exposed paths", "Sensitive fields auto-skipped"],
        [[k.get("forms_tested", 0), k.get("uploads_tested", 0), k.get("exposure_critical", 0), sum(len(f.get("skipped_sensitive") or []) for f in rep.get("forms", []))]])

    def sc_chart(ax):
        names, vals = list(rep["scores"]), list(rep["scores"].values())
        ax.barh(names[::-1], vals[::-1], color=[f"#{_score_color(v)}" for v in vals[::-1]])
        ax.set_xlim(0, 100)
        ax.set_title("Scores by area")
        for i, v in enumerate(vals[::-1]):
            ax.text(v + 1, i, str(v), va="center")
    d.add_picture(_chart_png(sc_chart), width=Inches(6.2))

    # ---- findings
    h("Key findings & recommendations", 1)
    if not rep["insights"]:
        d.add_paragraph("No issues were detected.")
    else:
        tbl(["Severity", "Area", "Finding", "Recommended fix", "Affected"],
            [[f["severity"].upper(), f["area"], f["title"] + (f"\n{f['detail']}" if f["detail"] else ""), f["fix"], f["count"] or "-"] for f in rep["insights"]],
            [0.8, 0.9, 2.6, 2.3, 0.6], sev_col=0, font=8.5)

    # ---- categories
    h("Screens grouped by category", 1)
    tbl(["Category", "Status", "Pages", "Tested", "Errors", "JS errors", "Avg load ms", "Max load ms", "Avg KB"],
        [[c["name"], c["status"], c["pages"], c["tested"], c["errors"], c["console_errors"], c["avg_load"], c["max_load"], c["avg_size_kb"]] for c in rep["categories"]],
        font=8.5)
    cats = [c for c in rep["categories"] if c["avg_load"]]
    if cats:
        def cat_chart(ax):
            cs = sorted(cats, key=lambda c: -c["avg_load"])[:14]
            ax.bar([c["name"][:14] for c in cs], [c["avg_load"] for c in cs], color="#0D9488")
            ax.axhline(2500, color="#DC2626", ls="--", lw=1)
            ax.set_title("Average load time by category (ms) - red line = 2.5 s")
            ax.tick_params(axis="x", rotation=40, labelsize=8)
        d.add_picture(_chart_png(cat_chart), width=Inches(6.2))

    # ---- page details
    h("Page-by-page results", 1)
    for c in rep["categories"]:
        h(c["name"], 2)
        rows = []
        for p in rep["pages"]:
            if p["category"] != c["name"]:
                continue
            rows.append([p["url"].replace(rep["meta"]["url"].rstrip("/"), "") or "/", p.get("status") or p["state"], p.get("ttfb") or "", p.get("load") or "",
                         p.get("lcp") or "", p.get("size_kb") or "", len(p.get("console_errors", [])) + len(p.get("page_errors", [])),
                         "login" if p.get("requires_login") else ""])
        tbl(["Path", "HTTP", "TTFB", "Load ms", "LCP", "KB", "JS err", "Note"], rows, [2.8, 0.55, 0.6, 0.7, 0.6, 0.6, 0.5, 0.6], font=8)

    # ---- load test
    s = rep.get("stress")
    h("Load & stress test", 1)
    if s and s.get("ran"):
        ov = s["overall"]
        tbl(["Peak req/s", "p50", "p95", "p99", "Max", "Error rate", "Degrades at", "Requests"],
            [[ov["rps"], f"{ov['p50']:.0f} ms", f"{ov['p95']:.0f} ms", f"{ov['p99']:.0f} ms", f"{ov['max']:.0f} ms", f"{ov['err_rate']}%",
              f"{s['breaking_users']} users" if s["breaking_users"] else "not reached", s["total_requests"]]])
        if s["steps"]:
            def ramp(ax):
                us = [x["users"] for x in s["steps"]]
                ax.plot(us, [x["p50"] for x in s["steps"]], marker="o", label="p50", color="#0D9488")
                ax.plot(us, [x["p95"] for x in s["steps"]], marker="o", label="p95", color="#EA580C")
                ax2 = ax.twinx()
                ax2.plot(us, [x["rps"] for x in s["steps"]], marker="s", ls="--", color="#2563EB", label="req/s")
                ax.set_xlabel("virtual users")
                ax.set_ylabel("latency (ms)")
                ax2.set_ylabel("req/s")
                ax.set_title("Latency & throughput as concurrency ramps up")
                ax.legend(loc="upper left")
            d.add_picture(_chart_png(ramp), width=Inches(6.2))
            tbl(["Users", "Requests", "Req/s", "p50", "p95", "p99", "Error %"], [[x["users"], x["requests"], x["rps"], x["p50"], x["p95"], x["p99"], x["err_rate"]] for x in s["steps"]])
        d.add_paragraph("Slowest pages under load (by p95):")
        pp = sorted(s["per_page"].values(), key=lambda x: -x["p95"])[:12]
        tbl(["URL", "Req", "p50", "p95", "p99", "Err %"], [[x["url"][-70:], x["requests"], x["p50"], x["p95"], x["p99"], x["err_rate"]] for x in pp], [3.4, 0.5, 0.6, 0.6, 0.6, 0.5], font=8)
    else:
        d.add_paragraph("The load test was not executed for this run.")

    if rep["broken_links"]:
        h("Broken links", 1)
        tbl(["Source", "Broken target", "Status"], [[b["source"][-60:], b["target"][-60:], b["status"]] for b in rep["broken_links"][:80]], [2.8, 3.2, 0.7], font=8)

    # ---- forms
    forms = rep.get("forms", [])
    if forms:
        h("Form testing & validation", 1)
        d.add_paragraph(f"{len(forms)} form(s) were filled with clearly-marked test_ data and submitted. "
                        "Payment/ID-style fields (card number, CVV, SSN, bank details) are detected by name/label and skipped automatically.")
        rows = []
        for f in forms:
            if "error" in f and "cases" not in f:
                rows.append([f["page"][-45:], f.get("method", ""), "could not be tested", f["error"][:70]])
                continue
            sub = f.get("submission") or {}
            sub_txt = "not submitted" if sub.get("skipped") or not sub.get("submitted") else sub.get("outcome", "unclear")
            case_txt = "; ".join(f"{c['case']}: {'OK' if c['pass'] else 'check'}" for c in f.get("cases", [])) or "no validation cases applicable"
            rows.append([f["page"][-45:], f["method"], case_txt[:90], sub_txt])
        tbl(["Page", "Method", "Validation cases", "Final submission"], rows, [2.2, 0.6, 2.8, 1.1], font=8)

    # ---- upload security
    uploads = rep.get("uploads", [])
    if uploads:
        h("File upload security", 1)
        bad = [u for u in uploads if u.get("executed") is True]
        if bad:
            p = d.add_paragraph(); r = p.add_run(f"CRITICAL: {len(bad)} upload accepted and executed a disguised script server-side (remote code execution).")
            r.bold = True; r.font.color.rgb = RGBColor.from_string(SEV_COLOR["critical"])
        def exec_txt2(u):
            if u.get("executed") is True:
                return "EXECUTED"
            if u.get("content_type_risk"):
                return "renderable"
            return "no" if u.get("executed") is False else "n/a"
        tbl(["Page", "Field", "Test case", "Filename", "Response", "Executed/renderable"],
            [[u["page"][-40:], u["field"][:18], u["case"], u["filename"][-28:], u["status"], exec_txt2(u)] for u in uploads],
            [1.9, 1.0, 1.3, 1.5, 0.8, 0.9], font=7.5)

    # ---- exposure
    sqlf = rep.get("sql_findings") or []
    if sqlf:
        h("SQL injection (error-based)", 1)
        d.add_paragraph("A single-quote probe on one parameter caused a database error to surface - input reaches SQL unsanitised. Read-only probe; no data was modified.")
        tbl(["Parameter", "Endpoint", "DB error evidence"], [[s["param"], s["url"][-55:], s["evidence"][:70]] for s in sqlf], [1.3, 2.9, 2.6], font=8)

    dscan = rep.get("directory_scan") or {}
    if dscan.get("groups"):
        h("Directory scan - directly accessible", 1)
        assets = ", ".join(f"{v} {k.lower()}" for k, v in (dscan.get("asset_counts") or {}).items())
        d.add_paragraph(f"{dscan.get('checked_dirs',0)} folder(s) and {dscan.get('checked_files',0)} file(s) probed directly over HTTP." +
                        (f" Expected public assets reachable (not flagged): {assets}." if assets else ""))
        for g in dscan["groups"]:
            hp = d.add_paragraph(); run = hp.add_run(f"{g['group']} ({g['count']})"); run.bold = True; run.font.size = Pt(10)
            tbl(["Severity", "Path", "HTTP", "Why"], [[it["severity"].upper(), it["path"][-60:], it["status"], it["reason"][:70]] for it in g["items"][:60]],
                [0.9, 2.4, 0.6, 3.3], sev_col=0, font=7.5)

    exp = rep.get("exposure", {})
    if exp.get("findings"):
        h("Known sensitive paths", 1)
        d.add_paragraph("Common sensitive paths checked anonymously, with no login session, to see what any visitor or bot could reach.")
        tbl(["Severity", "Path", "HTTP", "Why it matters"], [[e["severity"].upper(), e["path"], e["status"], e["reason"][:80]] for e in exp["findings"]],
            [0.9, 2.2, 0.6, 3.5], sev_col=0, font=8)

    lf = rep.get("local_files", {})
    fsres = lf.get("result")
    if fsres and fsres.get("ok"):
        h("Local project folder scan", 1)
        d.add_paragraph(f"Root: {fsres['root']}" + (f"  |  detected web root: {fsres['web_root']}" if fsres.get("web_root") else "  |  no web/ subfolder detected") +
                        f"  —  {fsres['files_scanned']} files / {fsres['dirs_scanned']} folders scanned.")
        if lf.get("findings"):
            tbl(["Severity", "Path", "Category", "In web root?"],
                [[f["severity"].upper(), f["rel_root"][-55:], f["category"], "YES" if f["in_web_root"] else ""] for f in lf["findings"]],
                [0.9, 3.2, 1.3, 0.9], sev_col=0, font=8)
        else:
            d.add_paragraph("No risky files were found on disk.")

    ab = rep.get("action_buttons", [])
    if ab:
        h("Action buttons (Create / Edit / Delete)", 1)
        d.add_paragraph("Inventoried from each control's HTML attributes only (href, data-confirm, data-method) - nothing was clicked.")
        tbl(["Page", "Type", "Label", "Has confirm?", "Confirm message"],
            [[a["page"][-40:], a["type"].upper(), a["label"][:24], "Yes" if a["has_confirm"] else "No", a["confirm_message"][:70]] for a in ab],
            [2.0, 0.7, 1.1, 0.8, 1.8], font=7.5)

    scope = rep.get("scope") or {}
    if scope.get("base_url"):
        h("Base URL scope check", 1)
        d.add_paragraph(f"Configured base URL: {scope['base_url']}  -  {scope.get('total_calls', 0)} GET/POST call(s) observed, "
                        f"{len(scope.get('out_of_base', []))} outside this base URL.")
        if scope.get("out_of_base"):
            tbl(["URL", "Method", "Status"], [[c["url"][-70:], c["method"], c["status"]] for c in scope["out_of_base"][:40]], [3.6, 0.7, 0.7], font=8)

    # ---- screenshots
    h("Screen previews", 1)
    n = 0
    for c in rep["categories"]:
        for p in rep["pages"]:
            if p["category"] != c["name"] or not p.get("shot") or p.get("alias_of") or n >= 30:
                continue
            buf = _thumb(os.path.join(shots_dir, p["shot"]), 900)
            if not buf:
                continue
            cap = d.add_paragraph()
            run = cap.add_run(f"{c['name']}  -  {p['url']}  (HTTP {p.get('status')}, {p.get('load')} ms)")
            run.bold, run.font.size = True, Pt(9)
            d.add_picture(buf, width=Inches(5.6))
            n += 1
    d.add_paragraph("\nGenerated by StressScope. Scores and recommendations are rule-based heuristics - validate critical findings manually.").runs[0].italic = True
    d.save(out_path)
