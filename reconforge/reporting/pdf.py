from __future__ import annotations

from pathlib import Path
from typing import Any


def _esc(text: Any) -> str:
    return str(text if text is not None else "")


def _confirmed(f: dict[str, Any]) -> bool:
    state = str(f.get("evidence_state") or "").upper()
    validation = str(f.get("validation_status") or "").lower()
    return state in {"CONFIRMED_OBSERVED", "CONFIRMED_DERIVED"} or validation in {"confirmed", "corroborated"}


def _severity_style(sev: str):
    from reportlab.lib import colors
    s = str(sev).lower()
    return {
        "critical": colors.HexColor("#991b1b"),
        "high": colors.HexColor("#c2410c"),
        "medium": colors.HexColor("#a16207"),
        "low": colors.HexColor("#1d4ed8"),
        "info": colors.HexColor("#475569"),
    }.get(s, colors.HexColor("#475569"))


def write_pdf_report(report: dict[str, Any], output_dir: Path) -> Path:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "report.pdf"

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="CoverTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=22,
        leading=26, textColor=colors.HexColor("#dc2626"), alignment=TA_CENTER, spaceAfter=7,
    ))
    styles.add(ParagraphStyle(
        name="CoverSub", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=9.5,
        leading=12, textColor=colors.HexColor("#475569"), alignment=TA_CENTER, spaceAfter=16,
    ))
    styles.add(ParagraphStyle(
        name="RFH2", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=13,
        leading=16, textColor=colors.HexColor("#0f172a"), spaceBefore=10, spaceAfter=7,
    ))
    styles.add(ParagraphStyle(
        name="RFH3", parent=styles["Heading3"], fontName="Helvetica-Bold", fontSize=10.5,
        leading=13, textColor=colors.HexColor("#111827"), spaceBefore=7, spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="BodyRF", parent=styles["BodyText"], fontName="Helvetica", fontSize=8.8,
        leading=12, textColor=colors.HexColor("#1f2937"), spaceAfter=5,
    ))
    styles.add(ParagraphStyle(
        name="SmallRF", parent=styles["BodyText"], fontName="Helvetica", fontSize=7.6,
        leading=10, textColor=colors.HexColor("#64748b"), spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="CommandRF", parent=styles["BodyText"], fontName="Courier", fontSize=7.1,
        leading=9.4, textColor=colors.HexColor("#0f172a"), backColor=colors.HexColor("#f8fafc"),
        borderColor=colors.HexColor("#cbd5e1"), borderWidth=0.5, borderPadding=5, spaceBefore=3,
        spaceAfter=5,
    ))
    styles.add(ParagraphStyle(
        name="FindingTitle", parent=styles["Heading3"], fontName="Helvetica-Bold", fontSize=11,
        leading=14, textColor=colors.HexColor("#0f172a"), spaceAfter=4,
    ))

    meta = report.get("meta", {})
    findings = report.get("findings", [])
    suppressed = report.get("not_reported", [])
    counts = {sev: sum(1 for f in findings if str(f.get("severity", "")).lower() == sev) for sev in ("critical", "high", "medium", "low")}

    story = []
    story.append(Spacer(1, 18 * mm))
    story.append(Paragraph("RECONFORGE", styles["CoverTitle"]))
    story.append(Paragraph("OFFENSIVE SECURITY ASSESSMENT REPORT", styles["CoverSub"]))
    cover_data = [
        [Paragraph("Target", styles["SmallRF"]), Paragraph(_esc(meta.get("target")), styles["BodyRF"])],
        [Paragraph("Assessment", styles["SmallRF"]), Paragraph(_esc(meta.get("assessment") or "-"), styles["BodyRF"])],
        [Paragraph("Client", styles["SmallRF"]), Paragraph(_esc(meta.get("client") or "-"), styles["BodyRF"])],
        [Paragraph("Scan", styles["SmallRF"]), Paragraph(_esc(meta.get("scan_id") or "-"), styles["BodyRF"])],
        [Paragraph("Mode", styles["SmallRF"]), Paragraph(_esc(meta.get("mode") or "-"), styles["BodyRF"])],
        [Paragraph("Methodology", styles["SmallRF"]), Paragraph("OWASP Top 10:2025 + MITRE CWE Top 25:2025 mappings", styles["BodyRF"])],
    ]
    cover = Table(cover_data, colWidths=[33 * mm, 130 * mm], hAlign="CENTER")
    cover.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#f1f5f9")),
        ("BOX", (0,0), (-1,-1), 0.6, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0,0), (-1,-1), 0.35, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 6), ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING", (0,0), (-1,-1), 6), ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(cover)
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("Only findings and concise suppression reasons are included in this report. Raw scanner payloads are intentionally omitted.", styles["SmallRF"]))
    story.append(PageBreak())

    story.append(Paragraph("EXECUTIVE FINDINGS", styles["RFH2"]))
    summary_rows = [[Paragraph("Critical", styles["SmallRF"]), Paragraph("High", styles["SmallRF"]), Paragraph("Medium", styles["SmallRF"]), Paragraph("Low", styles["SmallRF"]), Paragraph("Total", styles["SmallRF"])],
                    [str(counts['critical']), str(counts['high']), str(counts['medium']), str(counts['low']), str(len(findings))]]
    summary_table = Table(summary_rows, colWidths=[29 * mm] * 5, hAlign="LEFT")
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#e2e8f0")),
        ("BOX", (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0,0), (-1,-1), 0.35, colors.HexColor("#e2e8f0")),
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("FONTSIZE", (0,1), (-1,1), 13), ("FONTNAME", (0,1), (-1,1), "Helvetica-Bold"),
        ("TOPPADDING", (0,0), (-1,-1), 6), ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 5 * mm))

    if not findings:
        story.append(Paragraph("No reportable findings were identified by the configured assessment pipeline.", styles["BodyRF"]))
    else:
        for idx, f in enumerate(findings, start=1):
            sev = str(f.get("severity") or "info").lower()
            title = f"{idx}. {_esc(f.get('name') or 'Unnamed finding')} [{sev.upper()}]"
            endpoint = f.get("endpoint") or (f.get("endpoints") or ["-"])[0]
            source = ", ".join(f.get("sources") or []) or "ReconForge audit"
            state = f.get("evidence_state") or "SCANNER_REPORTED"
            why = f.get("why_reported") or "Observed by the ReconForge evidence pipeline."
            owasp = f.get("owasp_category") or f.get("owasp_2025_id") or "-"
            cwe = f.get("cwe") or f.get("cwe_top25_2025_id") or "-"

            blocks = [Paragraph(title, styles["FindingTitle"])]
            detail_rows = [
                [Paragraph("Affected endpoint", styles["SmallRF"]), Paragraph(_esc(endpoint), styles["BodyRF"])],
                [Paragraph("Why reported", styles["SmallRF"]), Paragraph(_esc(why), styles["BodyRF"])],
                [Paragraph("Evidence state", styles["SmallRF"]), Paragraph(_esc(state), styles["BodyRF"])],
                [Paragraph("Source(s)", styles["SmallRF"]), Paragraph(_esc(source), styles["BodyRF"])],
                [Paragraph("OWASP / CWE", styles["SmallRF"]), Paragraph(f"{_esc(owasp)} / {_esc(cwe)}", styles["BodyRF"])],
            ]
            t = Table(detail_rows, colWidths=[33 * mm, 130 * mm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#f8fafc")),
                ("BOX", (0,0), (-1,-1), 0.4, colors.HexColor("#dbe3ea")),
                ("INNERGRID", (0,0), (-1,-1), 0.25, colors.HexColor("#e5e7eb")),
                ("VALIGN", (0,0), (-1,-1), "TOP"),
                ("LEFTPADDING", (0,0), (-1,-1), 5), ("RIGHTPADDING", (0,0), (-1,-1), 5),
                ("TOPPADDING", (0,0), (-1,-1), 4), ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ]))
            blocks.append(t)

            if _confirmed(f):
                description = f.get("description") or f"{f.get('name')} was directly observed or deterministically derived from assessment evidence."
                impact = f.get("impact") or "The observed weakness may reduce the application's security boundary or expose protected functionality/data."
                remediation = f.get("remediation") or "Apply the appropriate secure configuration or application control and retest the affected endpoint."
                blocks.extend([
                    Paragraph("Description", styles["RFH3"]), Paragraph(_esc(description), styles["BodyRF"]),
                    Paragraph("Impact", styles["RFH3"]), Paragraph(_esc(impact), styles["BodyRF"]),
                    Paragraph("Remediation", styles["RFH3"]), Paragraph(_esc(remediation), styles["BodyRF"]),
                ])
            else:
                guidance = f.get("manual_validation") or "Manually validate the candidate in a controlled authorized workflow before treating it as confirmed."
                blocks.extend([
                    Paragraph("Manual validation", styles["RFH3"]), Paragraph(_esc(guidance), styles["BodyRF"]),
                ])

            commands = f.get("source_commands") or {}
            if commands:
                blocks.append(Paragraph("Command used", styles["RFH3"]))
                for src, cmd in commands.items():
                    blocks.append(Paragraph(f"{_esc(src)}: { _esc(cmd) }", styles["CommandRF"]))
            story.append(KeepTogether(blocks))
            story.append(Spacer(1, 4 * mm))

    story.append(Paragraph("SUPPRESSED / FALSE-POSITIVE CHECKS", styles["RFH2"]))
    if suppressed:
        rows = [[Paragraph("Candidate", styles["SmallRF"]), Paragraph("Reason", styles["SmallRF"])]]
        for item in suppressed:
            rows.append([Paragraph(_esc(item.get("candidate") or "-"), styles["BodyRF"]), Paragraph(_esc(item.get("reason") or "Not reproduced by validation."), styles["BodyRF"])])
        st = Table(rows, colWidths=[70 * mm, 93 * mm], repeatRows=1)
        st.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#e2e8f0")),
            ("BOX", (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0,0), (-1,-1), 0.3, colors.HexColor("#e5e7eb")),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("TOPPADDING", (0,0), (-1,-1), 5), ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ]))
        story.append(st)
    else:
        story.append(Paragraph("No findings were suppressed as false positives or not reproduced in this run.", styles["SmallRF"]))

    story.append(Spacer(1, 7 * mm))
    story.append(Paragraph("Operator note: ReconForge identifies and documents findings; exploit execution and destructive validation remain operator-controlled.", styles["SmallRF"]))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(15 * mm, 9 * mm, "ReconForge 4.5.0")
        canvas.drawRightString(A4[0] - 15 * mm, 9 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        str(path), pagesize=A4, rightMargin=15 * mm, leftMargin=15 * mm,
        topMargin=14 * mm, bottomMargin=14 * mm, title="ReconForge Security Assessment Report",
        author="ReconForge",
    )
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return path
