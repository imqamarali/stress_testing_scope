"""Benign, inert test payloads for file-upload security testing.

Everything here is a passive detection beacon (prints a marker string) or plain
filler bytes. Nothing here reads files, executes commands, opens a network
connection, or persists itself - it only proves whether the server accepted
and/or executed an upload it should have rejected.
"""
from __future__ import annotations

import base64

# a valid, minimal 1x1 transparent PNG - used as the "legitimate" control upload
PNG_1PX = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


def marker_php(token: str) -> bytes:
    """Passive beacon: if this executes server-side, fetching the uploaded URL returns the token."""
    return f'<?php echo "STRESSSCOPE_UPLOAD_OK_{token}"; ?>'.encode()


def marker_html(token: str) -> bytes:
    return f"<html><body>STRESSSCOPE_UPLOAD_OK_{token}</body></html>".encode()


def marker_svg_script(token: str) -> bytes:
    # SVG can carry script content; many upload filters miss this. Beacon only, no action taken.
    return (f'<svg xmlns="http://www.w3.org/2000/svg"><text>STRESSSCOPE_UPLOAD_OK_{token}</text></svg>').encode()


def candidates(token: str, accept: str = "") -> list[dict]:
    """Return the set of upload test cases for one file field."""
    acc = (accept or "").lower()
    img_only = bool(acc) and "image" in acc and "/*" not in acc.replace("image/*", "") or acc == "image/*"
    cases = [
        {"case": "valid", "name": f"test_upload_{token}.png", "mime": "image/png", "data": PNG_1PX,
         "expect": "accepted", "note": "Legitimate small image - control case, should be accepted."},
        {"case": "mismatched_content", "name": f"test_upload_{token}.png", "mime": "image/png", "data": marker_html(token),
         "expect": "rejected_or_flagged", "note": "HTML content disguised with a .png extension/MIME - tests content-type sniffing, not just extension trust."},
        {"case": "double_extension", "name": f"test_upload_{token}.png.php", "mime": "image/png", "data": marker_php(token),
         "expect": "rejected", "note": "PHP beacon disguised with a double extension - tests for naive last-dot-only extension checks."},
        {"case": "svg_script", "name": f"test_upload_{token}.svg", "mime": "image/svg+xml", "data": marker_svg_script(token),
         "expect": "rejected_or_flagged", "note": "SVG can carry embedded markup/script - tests whether SVG uploads are sanitised."},
        {"case": "path_traversal_name", "name": f"../../test_traversal_{token}.txt", "mime": "text/plain", "data": f"test_{token}".encode(),
         "expect": "rejected_or_sanitised", "note": "Filename contains path traversal sequences - tests filename sanitisation."},
        {"case": "oversized", "name": f"test_upload_big_{token}.png", "mime": "image/png", "data": PNG_1PX + b"\x00" * (6 * 1024 * 1024),
         "expect": "rejected", "note": "6 MB file - tests whether an upload size limit is enforced."},
        {"case": "empty", "name": f"test_upload_empty_{token}.png", "mime": "image/png", "data": b"",
         "expect": "rejected_or_flagged", "note": "Zero-byte file - tests handling of empty uploads."},
    ]
    if not img_only:
        cases.insert(2, {"case": "executable_extension", "name": f"test_upload_{token}.php", "mime": "application/x-php", "data": marker_php(token),
                         "expect": "rejected", "note": "PHP beacon with its real extension - baseline unrestricted-upload test."})
    return cases
