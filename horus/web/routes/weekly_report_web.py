"""Weekly threat report generation and download."""

from __future__ import annotations

import os
import tempfile

from flask import Blueprint, Response, request, send_file

from horus.storage import db as _db_module
from horus.storage.weekly import gather_weekly_data

from .._render import error_page, page
from .auth import READ_ALL, role_required

bp = Blueprint("weekly_report", __name__)


@bp.route("/weekly-report")
@role_required(*READ_ALL)
def weekly_report_page():
    """Weekly report generation page."""
    return page(
        "weekly_report.html",
        title="Weekly Report",
        active="weekly-report",
    )


@bp.route("/weekly-report/generate", methods=["POST"])
@role_required(*READ_ALL)
def generate_weekly_report():
    """Generate and download the weekly report."""
    fmt = request.args.get("format", "html")
    weeks_back = request.args.get("weeks_back", 1, type=int)

    with _db_module.connect() as conn:
        weekly_data = gather_weekly_data(conn, weeks_back=weeks_back)

    from horus.render.weekly import render_weekly_report

    report = render_weekly_report(weekly_data, fmt=fmt)

    if fmt == "pdf":
        # Convert HTML to PDF
        try:
            from playwright.sync_api import sync_playwright

            with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
                f.write(report.encode("utf-8"))
                html_path = f.name

            pdf_path = html_path.replace(".html", ".pdf")
            with sync_playwright() as p:
                browser = p.chromium.launch()
                pg = browser.new_page()
                pg.goto(f"file://{html_path}")
                pg.wait_for_timeout(3000)
                pg.evaluate("""() => {
                    document.querySelectorAll('svg').forEach(s => {
                        s.setAttribute('width', s.getBoundingClientRect().width);
                        s.setAttribute('height', s.getBoundingClientRect().height);
                    });
                }""")
                pg.pdf(
                    path=pdf_path,
                    format="A4",
                    margin={"top": "12mm", "bottom": "12mm", "left": "12mm", "right": "12mm"},
                    print_background=True,
                    prefer_css_page_size=True,
                    scale=0.85,
                    display_header_footer=True,
                    footer_template='<div style="font-size:8pt;width:100%;text-align:center;color:#888;padding:0 1cm;"><span class="pageNumber"></span> / <span class="totalPages"></span></div>',
                    header_template="<div></div>",
                )
                browser.close()

            os.unlink(html_path)
            return send_file(
                pdf_path,
                mimetype="application/pdf",
                as_attachment=True,
                download_name=f"weekly-report-{weekly_data.period_start}-to-{weekly_data.period_end}.pdf",
            )
        except Exception as e:
            return error_page(f"PDF generation failed: {e}"), 500

    # For HTML/text/md, return as downloadable file
    mimetypes = {"html": "text/html", "md": "text/markdown", "text": "text/plain"}
    ext = {"html": "html", "md": "md", "text": "txt"}
    return Response(
        report,
        mimetype=mimetypes.get(fmt, "text/plain"),
        headers={
            "Content-Disposition": f"attachment; filename=weekly-report-{weekly_data.period_start}-to-{weekly_data.period_end}.{ext.get(fmt, 'txt')}"
        },
    )
