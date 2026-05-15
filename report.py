import sqlite3
import io
import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.platypus.flowables import HRFlowable

# ── Colour palette ────────────────────────────────────────────────────────────
C_DARK     = colors.HexColor("#0F172A")   # slate-900  — page header/footer bg
C_PRIMARY  = colors.HexColor("#1E40AF")   # blue-800   — section headings
C_ACCENT   = colors.HexColor("#3B82F6")   # blue-500   — table header bg
C_LIGHT    = colors.HexColor("#EFF6FF")   # blue-50    — alt table row
C_WHITE    = colors.white
C_DIVIDER  = colors.HexColor("#CBD5E1")   # slate-300

SEV_HIGH   = colors.HexColor("#DC2626")   # red-600
SEV_MED    = colors.HexColor("#D97706")   # amber-600
SEV_LOW    = colors.HexColor("#16A34A")   # green-600
SEV_DEF    = colors.HexColor("#6B7280")   # gray-500

DB_PATH = "fim.db"


# ── Database helpers ──────────────────────────────────────────────────────────

def _connect():
    """WAL mode so PDF generation never blocks monitor.py writes.
    Without WAL, generating a report while the monitor is actively
    writing alerts causes "database is locked" and an empty report.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _fetch_summary():
    conn = _connect()
    c = conn.cursor()
    stats = {}

    for table, label in [("baseline", "files_monitored"),
                          ("alerts",   "total_alerts"),
                          ("audit_log","audit_entries"),
                          ("chained_alerts", "chain_entries")]:
        try:
            c.execute(f"SELECT COUNT(*) FROM {table}")
            stats[label] = c.fetchone()[0]
        except Exception:
            stats[label] = 0

    for sev in ("HIGH", "MEDIUM", "LOW"):
        try:
            c.execute("SELECT COUNT(*) FROM alerts WHERE severity = ?", (sev,))
            stats[f"sev_{sev.lower()}"] = c.fetchone()[0]
        except Exception:
            stats[f"sev_{sev.lower()}"] = 0

    try:
        c.execute("""
            SELECT mitre_technique, COUNT(*) as cnt
            FROM alerts
            WHERE mitre_technique IS NOT NULL AND mitre_technique != ''
            GROUP BY mitre_technique
            ORDER BY cnt DESC
            LIMIT 8
        """)
        stats["mitre_breakdown"] = c.fetchall()
    except Exception:
        stats["mitre_breakdown"] = []

    try:
        c.execute("""
            SELECT event_type, COUNT(*) as cnt
            FROM alerts
            GROUP BY event_type
            ORDER BY cnt DESC
        """)
        stats["event_breakdown"] = c.fetchall()
    except Exception:
        stats["event_breakdown"] = []

    conn.close()
    return stats


def _fetch_alerts(limit=50):
    conn = _connect()
    c = conn.cursor()
    try:
        c.execute("""
            SELECT timestamp, event_type, file_path, severity, mitre_technique, action_taken
            FROM alerts
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = c.fetchall()
    except Exception:
        rows = []
    conn.close()
    return rows


def _fetch_audit_log(limit=50):
    conn = _connect()
    c = conn.cursor()
    try:
        c.execute("""
            SELECT timestamp, username, action, details, success
            FROM audit_log
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = c.fetchall()
    except Exception:
        rows = []
    conn.close()
    return rows


# ── Style helpers ─────────────────────────────────────────────────────────────

def _build_styles():
    base = getSampleStyleSheet()

    def add(name, **kw):
        base.add(ParagraphStyle(name=name, **kw))

    add("ReportTitle",
        fontSize=26, leading=32, textColor=C_WHITE,
        fontName="Helvetica-Bold", alignment=TA_CENTER, spaceAfter=4)

    add("ReportSubtitle",
        fontSize=12, leading=16, textColor=colors.HexColor("#93C5FD"),
        fontName="Helvetica", alignment=TA_CENTER, spaceAfter=2)

    add("CoverMeta",
        fontSize=10, leading=14, textColor=colors.HexColor("#CBD5E1"),
        fontName="Helvetica", alignment=TA_CENTER)

    add("SectionHeading",
        fontSize=14, leading=18, textColor=C_PRIMARY,
        fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=6)

    add("SubHeading",
        fontSize=11, leading=14, textColor=C_DARK,
        fontName="Helvetica-Bold", spaceBefore=8, spaceAfter=4)

    add("FIMBody",
        fontSize=9, leading=13, textColor=C_DARK,
        fontName="Helvetica", spaceAfter=4)

    add("TableCell",
        fontSize=8, leading=11, textColor=C_DARK,
        fontName="Helvetica")

    add("TableCellBold",
        fontSize=8, leading=11, textColor=C_DARK,
        fontName="Helvetica-Bold")

 
    add("TableCellPath",
        fontSize=7.5, leading=10, textColor=C_DARK,
        fontName="Helvetica", wordWrap="CJK")

    add("Severity_HIGH",
        fontSize=8, leading=11, textColor=C_WHITE,
        fontName="Helvetica-Bold")

    add("FooterText",
        fontSize=8, leading=10, textColor=colors.HexColor("#94A3B8"),
        fontName="Helvetica", alignment=TA_CENTER)

    return base


# ── Page template (header / footer) ──────────────────────────────────────────

class _HeaderFooterCanvas:
    """Mixin that draws a persistent header and footer on every page except page 1."""

    def __init__(self, *args, generated_at, **kwargs):
        self._generated_at = generated_at

    # Called by SimpleDocTemplate via onFirstPage / onLaterPages callbacks

def _on_first_page(canvas, doc):
    pass   # Cover page — no header/footer chrome


def _on_later_pages(canvas, doc):
    w, h = A4
    canvas.saveState()

    # ── header bar ──
    canvas.setFillColor(C_DARK)
    canvas.rect(0, h - 1.1 * cm, w, 1.1 * cm, fill=1, stroke=0)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.setFillColor(C_WHITE)
    canvas.drawString(1.5 * cm, h - 0.75 * cm, "FIM Security Report")
    canvas.setFont("Helvetica", 9)
    canvas.drawRightString(w - 1.5 * cm, h - 0.75 * cm,
                           f"Generated: {doc.report_generated_at}")

    # ── footer bar ──
    canvas.setFillColor(C_DARK)
    canvas.rect(0, 0, w, 0.9 * cm, fill=1, stroke=0)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#94A3B8"))
    canvas.drawString(1.5 * cm, 0.3 * cm, "Real-Time File Integrity Monitor")
    canvas.drawRightString(w - 1.5 * cm, 0.3 * cm, f"Page {doc.page}")

    canvas.restoreState()


# ── Cover page ────────────────────────────────────────────────────────────────

def _build_cover(styles, generated_at, stats):
    story = []
    w, h = A4

    # Dark full-width banner drawn via a 1-row table (works inside Platypus flow)
    banner_content = [
        [Paragraph("&#127737;  File Integrity Monitor", styles["ReportTitle"])],
        [Paragraph("Security Incident Report", styles["ReportSubtitle"])],
        [Spacer(1, 0.3 * cm)],
        [Paragraph(f"Generated: {generated_at}", styles["CoverMeta"])],
    ]
    banner_table = Table(banner_content, colWidths=[w - 4 * cm])
    banner_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_DARK),
        ("TOPPADDING",    (0, 0), (-1, 0),  28),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 28),
        ("LEFTPADDING",   (0, 0), (-1, -1), 24),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 24),
        ("ROUNDEDCORNERS", [8]),
    ]))
    story.append(banner_table)
    story.append(Spacer(1, 1 * cm))

    # ── KPI grid (2 × 3) ──

    kpi_value_style = ParagraphStyle(
        "KPIValue", parent=styles["FIMBody"],
        fontSize=22, leading=26, alignment=TA_CENTER,
        textColor=C_PRIMARY, spaceAfter=2,
    )
    kpi_label_style = ParagraphStyle(
        "KPILabel", parent=styles["FIMBody"],
        fontSize=10, leading=12, alignment=TA_CENTER,
        textColor=colors.HexColor("#475569"),
    )

    def kpi_cell(label, value, value_colour=C_PRIMARY):
        """Build a centered 2-row card: big value on top, label underneath."""
        v_style = ParagraphStyle(
            "KPIValueColored", parent=kpi_value_style,
            textColor=value_colour,
        )
        cell = Table(
            [
                [Paragraph(f"<b>{value}</b>", v_style)],
                [Paragraph(label, kpi_label_style)],
            ],
            colWidths=[5.5 * cm],
            rowHeights=[1.2 * cm, 0.9 * cm],
        )
        cell.setStyle(TableStyle([
            ("ALIGN",   (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",  (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING",   (0, 0), (-1, -1), 4),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
            ("TOPPADDING",    (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        return cell

    kpi_data = [
        [
            kpi_cell("Files Monitored", stats["files_monitored"]),
            kpi_cell("Total Alerts",    stats["total_alerts"]),
            kpi_cell("Log Entries",     stats["audit_entries"]),
        ],
        [
            kpi_cell("HIGH Severity",   stats["sev_high"],   SEV_HIGH),
            kpi_cell("MEDIUM Severity", stats["sev_medium"], SEV_MED),
            kpi_cell("LOW Severity",    stats["sev_low"],    SEV_LOW),
        ],
    ]
    kpi_table = Table(kpi_data, colWidths=[5.5 * cm, 5.5 * cm, 5.5 * cm],
                      rowHeights=[2.4 * cm, 2.4 * cm])
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX",          (0, 0), (-1, -1), 0.5, C_DIVIDER),
        ("INNERGRID",    (0, 0), (-1, -1), 0.5, C_DIVIDER),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 0.8 * cm))

    # ── Scope note ──
    story.append(HRFlowable(width="100%", thickness=1, color=C_DIVIDER))
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph(
        "This report summarises file integrity events, severity classification, "
        "MITRE ATT&amp;CK technique mapping, and user activity recorded by the "
        "Real-Time File Integrity Monitor. Data covers the most recent 50 alerts "
        "and 50 log report entries at the time of generation.",
        styles["FIMBody"]
    ))
    story.append(PageBreak())
    return story


# ── Summary section ───────────────────────────────────────────────────────────

def _severity_badge_style(sev):
    colour_map = {"HIGH": SEV_HIGH, "MEDIUM": SEV_MED, "LOW": SEV_LOW}
    return colour_map.get(sev, SEV_DEF)


def _build_summary(styles, stats):
    story = []
    story.append(Paragraph("1. Executive Summary", styles["SectionHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_DIVIDER))
    story.append(Spacer(1, 0.3 * cm))

    # ── Event type breakdown ──
    story.append(Paragraph("Alert Breakdown by Event Type", styles["SubHeading"]))
    if stats["event_breakdown"]:
        header = [
            Paragraph("<b>Event Type</b>", styles["TableCellBold"]),
            Paragraph("<b>Count</b>",      styles["TableCellBold"]),
            Paragraph("<b>% of Total</b>", styles["TableCellBold"]),
        ]
        total = stats["total_alerts"] or 1
        rows = [header]
        for event_type, cnt in stats["event_breakdown"]:
            pct = f"{cnt / total * 100:.1f}%"
            rows.append([
                Paragraph(event_type or "—", styles["TableCell"]),
                Paragraph(str(cnt), styles["TableCell"]),
                Paragraph(pct, styles["TableCell"]),
            ])
        t = Table(rows, colWidths=[8 * cm, 3 * cm, 3 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  C_ACCENT),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_LIGHT]),
            ("BOX",           (0, 0), (-1, -1), 0.5, C_DIVIDER),
            ("INNERGRID",     (0, 0), (-1, -1), 0.5, C_DIVIDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No alert data recorded yet.", styles["FIMBody"]))

    story.append(Spacer(1, 0.6 * cm))

    # ── MITRE breakdown ──
    story.append(Paragraph("MITRE ATT&amp;CK Technique Coverage", styles["SubHeading"]))
    if stats["mitre_breakdown"]:
        header = [
            Paragraph("<b>Technique ID</b>", styles["TableCellBold"]),
            Paragraph("<b>Alert Count</b>",  styles["TableCellBold"]),
        ]
        rows = [header]
        for technique, cnt in stats["mitre_breakdown"]:
            rows.append([
                Paragraph(technique or "—", styles["TableCell"]),
                Paragraph(str(cnt), styles["TableCell"]),
            ])
        t = Table(rows, colWidths=[11 * cm, 3 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  C_ACCENT),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_WHITE, C_LIGHT]),
            ("BOX",           (0, 0), (-1, -1), 0.5, C_DIVIDER),
            ("INNERGRID",     (0, 0), (-1, -1), 0.5, C_DIVIDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No MITRE technique data recorded yet.", styles["FIMBody"]))

    story.append(PageBreak())
    return story


# ── Alerts section ────────────────────────────────────────────────────────────

def _severity_colour(sev):
    return {
        "HIGH":   colors.HexColor("#FEE2E2"),
        "MEDIUM": colors.HexColor("#FEF3C7"),
        "LOW":    colors.HexColor("#DCFCE7"),
    }.get(sev, colors.HexColor("#F1F5F9"))


def _build_alerts_table(styles, alerts):
    story = []
    story.append(Paragraph("2. Recent Alerts", styles["SectionHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_DIVIDER))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(
        f"Showing the {len(alerts)} most recent alerts, newest first.",
        styles["FIMBody"]
    ))
    story.append(Spacer(1, 0.2 * cm))

    if not alerts:
        story.append(Paragraph("No alerts recorded yet.", styles["FIMBody"]))
        story.append(PageBreak())
        return story

    col_widths = [2.6 * cm, 1.9 * cm, 7.4 * cm, 1.7 * cm, 2.0 * cm]
    header = [
        Paragraph("<b>Timestamp</b>",      styles["TableCellBold"]),
        Paragraph("<b>Event</b>",          styles["TableCellBold"]),
        Paragraph("<b>File Path</b>",      styles["TableCellBold"]),
        Paragraph("<b>Severity</b>",       styles["TableCellBold"]),
        Paragraph("<b>MITRE</b>",          styles["TableCellBold"]),
    ]
    rows = [header]
    row_styles = []

    for i, (ts, event, path, sev, mitre, action) in enumerate(alerts, start=1):
        sev = sev or "—"
        rows.append([
            Paragraph(ts or "—",           styles["TableCell"]),
            Paragraph(event or "—",        styles["TableCell"]),
            Paragraph(path or "—",         styles["TableCellPath"]),
            Paragraph(f"<b>{sev}</b>",     styles["TableCell"]),
            Paragraph(mitre or "—",        styles["TableCell"]),
        ])
        # Colour entire row by severity
        bg = _severity_colour(sev)
        row_styles.append(("BACKGROUND", (0, i), (-1, i), bg))

    table_style = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_ACCENT),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("BOX",           (0, 0), (-1, -1), 0.5, C_DIVIDER),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, C_DIVIDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("WORDWRAP",      (0, 0), (-1, -1), True),
    ] + row_styles)

    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(table_style)
    story.append(t)
    story.append(PageBreak())
    return story


# ── Audit log section ─────────────────────────────────────────────────────────

def _build_audit_table(styles, audit_rows):
    story = []
    story.append(Paragraph("3. Log Report", styles["SectionHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_DIVIDER))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(
        f"Showing the {len(audit_rows)} most recent log entries. "
        "All authentication and administrative actions are recorded here for accountability.",
        styles["FIMBody"]
    ))
    story.append(Spacer(1, 0.2 * cm))

    if not audit_rows:
        story.append(Paragraph("No log entries yet.", styles["FIMBody"]))
        story.append(PageBreak())
        return story

    col_widths = [3.2 * cm, 2.8 * cm, 3.5 * cm, 5.0 * cm, 1.2 * cm]
    header = [
        Paragraph("<b>Timestamp</b>",  styles["TableCellBold"]),
        Paragraph("<b>Username</b>",   styles["TableCellBold"]),
        Paragraph("<b>Action</b>",     styles["TableCellBold"]),
        Paragraph("<b>Details</b>",    styles["TableCellBold"]),
        Paragraph("<b>OK</b>",         styles["TableCellBold"]),
    ]
    rows = [header]
    row_styles = []

    for i, (ts, username, action, details, success) in enumerate(audit_rows, start=1):
        ok_text = "&#10003;" if success else "&#10007;"
        ok_colour = SEV_LOW if success else SEV_HIGH
        rows.append([
            Paragraph(ts or "—",          styles["TableCell"]),
            Paragraph(username or "—",    styles["TableCell"]),
            Paragraph(action or "—",      styles["TableCell"]),
            Paragraph(details or "—",     styles["TableCell"]),
            Paragraph(f'<font color="#{ok_colour.hexval()[2:].upper()}"><b>{ok_text}</b></font>',
                      styles["TableCell"]),
        ])
        bg = C_LIGHT if i % 2 == 0 else C_WHITE
        row_styles.append(("BACKGROUND", (0, i), (-1, i), bg))
        if not success:
            row_styles.append(("BACKGROUND", (0, i), (-1, i),
                                colors.HexColor("#FEE2E2")))

    table_style = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_ACCENT),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("BOX",           (0, 0), (-1, -1), 0.5, C_DIVIDER),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, C_DIVIDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("WORDWRAP",      (0, 0), (-1, -1), True),
    ] + row_styles)

    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(table_style)
    story.append(t)
    return story


# ── Public API ────────────────────────────────────────────────────────────────

def generate_report_bytes(db_path=None) -> bytes:
    
    global DB_PATH
    if db_path:
        DB_PATH = db_path

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    styles   = _build_styles()
    stats    = _fetch_summary()
    alerts   = _fetch_alerts(limit=50)
    audit    = _fetch_audit_log(limit=50)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
        title="FIM Security Report",
        author="Real-Time File Integrity Monitor",
        subject="Security Incident Report",
    )
    # Attach metadata so page callbacks can access it
    doc.report_generated_at = generated_at

    story = []
    story += _build_cover(styles, generated_at, stats)
    story += _build_summary(styles, stats)
    story += _build_alerts_table(styles, alerts)
    story += _build_audit_table(styles, audit)

    doc.build(story,
              onFirstPage=_on_first_page,
              onLaterPages=_on_later_pages)

    return buf.getvalue()


# ── Standalone entry point ────────────────────────────────────────────────────

if __name__ == "__main__":
    out = "fim_report.pdf"
    print(f"Generating report from {DB_PATH} ...")
    pdf_bytes = generate_report_bytes()
    with open(out, "wb") as f:
        f.write(pdf_bytes)
    print(f"Report saved to {out}  ({len(pdf_bytes):,} bytes)")
