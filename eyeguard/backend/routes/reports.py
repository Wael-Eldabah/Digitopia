"""Software-only simulation / demo — no real systems will be contacted or modified."""
from __future__ import annotations

import csv
import json
from io import BytesIO, StringIO
from textwrap import wrap
from typing import Any, List

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response, StreamingResponse

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from ..models.schemas import Report, ReportDetail
from ..utils.state import state_store

router = APIRouter(prefix="/api/v1", tags=["reports"])


def _clone_report(report: Report) -> Report:
    return Report(**report.model_dump())




def _stringify(value: Any) -> str:
    if value is None:
        return 'N/A'
    if isinstance(value, str):
        return value or 'N/A'
    if isinstance(value, (list, dict)) and not value:
        return 'N/A'
    try:
        return json.dumps(value, default=str, ensure_ascii=False, indent=2)
    except TypeError:
        return str(value)


def _extract_indicators(report: ReportDetail) -> list[str]:
    indicators: list[str] = []

    summary = report.summary
    if isinstance(summary, dict):
        candidate = summary.get('indicators') or summary.get('indicator')
        if isinstance(candidate, str):
            indicators.append(candidate)
        elif isinstance(candidate, (list, tuple, set)):
            indicators.extend(str(item) for item in candidate if item)

    payload = report.payload if isinstance(report.payload, dict) else {}
    if isinstance(payload, dict):
        candidate = payload.get('indicators')
        if isinstance(candidate, str):
            indicators.append(candidate)
        elif isinstance(candidate, (list, tuple, set)):
            indicators.extend(str(item) for item in candidate if item)
        for entry in payload.get('alerts', []):
            indicator = entry.get('indicator')
            if indicator:
                indicators.append(str(indicator))
        for entry in payload.get('ips', []):
            ip = entry.get('ip')
            if ip:
                indicators.append(str(ip))

    cleaned: list[str] = []
    seen: set[str] = set()
    for indicator in indicators:
        normalized = str(indicator).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        cleaned.append(normalized)
    return cleaned


def _write_multiline(text_object, heading: str, content: str) -> None:
    text_object.textLine('')
    text_object.textLine(heading)
    normalized = content if content.strip() else 'N/A'
    for raw_line in normalized.splitlines():
        segments = wrap(raw_line, 85)
        if not segments:
            text_object.textLine(raw_line)
        else:
            for segment in segments:
                text_object.textLine(segment)


def _build_pdf(report: ReportDetail) -> bytes:
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    text_object = pdf.beginText(40, 750)
    text_object.textLine("EyeGuard Incident Report")
    text_object.textLine("")
    created_at = getattr(report, 'created_at', None)
    created_value = created_at.isoformat() if created_at else 'N/A'
    text_object.textLine(f"Report ID: {report.id}")
    text_object.textLine(f"Title: {report.title or 'N/A'}")
    text_object.textLine(f"Type: {report.type}")
    text_object.textLine(f"Created At: {created_value}")
    text_object.textLine(f"Contains Alerts: {'Yes' if report.has_alerts else 'No'}")

    summary_text = _stringify(report.summary)
    _write_multiline(text_object, 'Summary:', summary_text)

    indicators = _extract_indicators(report)
    if indicators:
        text_object.textLine('')
        text_object.textLine('Indicators:')
        for indicator in indicators:
            segments = wrap(indicator, 85)
            if not segments:
                text_object.textLine(f"- {indicator}")
            else:
                for index, segment in enumerate(segments):
                    prefix = '- ' if index == 0 else '  '
                    text_object.textLine(f"{prefix}{segment}")

    payload_text = _stringify(report.payload)
    if payload_text != 'N/A':
        _write_multiline(text_object, 'Payload Details:', payload_text)

    pdf.drawText(text_object)
    pdf.showPage()
    pdf.save()
    buffer.seek(0)
    return buffer.read()


@router.get("/reports", response_model=List[Report])
async def list_reports() -> list[Report]:
    async with state_store._lock:  # type: ignore[attr-defined]
        return [_clone_report(report) for report in state_store.reports.values()]


@router.get("/reports/{report_id}", response_model=ReportDetail)
async def get_report(report_id: str) -> ReportDetail:
    async with state_store._lock:  # type: ignore[attr-defined]
        report = state_store.reports.get(report_id)
        if not report:
            raise HTTPException(status_code=404, detail={"error_code": "REPORT_NOT_FOUND", "message": "Report not found"})
        payload = report.model_dump()
        analysis = state_store.get_pcap_analysis(report_id)
        if analysis:
            payload["payload"] = analysis
        return ReportDetail(**payload)


@router.get("/reports/{report_id}/export.csv")
async def export_report_csv(report_id: str) -> StreamingResponse:
    report_detail = await get_report(report_id)
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['field', 'value'])
    created_at = getattr(report_detail, 'created_at', None)
    created_value = created_at.isoformat() if created_at else ''
    writer.writerow(['report_id', report_detail.id])
    writer.writerow(['title', report_detail.title or ''])
    writer.writerow(['type', report_detail.type])
    writer.writerow(['created_at', created_value])
    writer.writerow(['has_alerts', 'yes' if report_detail.has_alerts else 'no'])
    writer.writerow(['summary', _stringify(report_detail.summary)])
    indicators = _extract_indicators(report_detail)
    if indicators:
        writer.writerow(['indicators', '; '.join(indicators)])
    payload_text = _stringify(report_detail.payload)
    if payload_text != 'N/A':
        writer.writerow(['payload', payload_text])
    output.seek(0)
    headers = {"Content-Disposition": f"attachment; filename=report-{report_detail.id}.csv"}
    return StreamingResponse(iter([output.getvalue()]), media_type='text/csv', headers=headers)


@router.get("/reports/{report_id}/export.pdf")
async def export_report_pdf(report_id: str) -> Response:
    report_detail = await get_report(report_id)
    payload = _build_pdf(report_detail)
    headers = {"Content-Disposition": f"attachment; filename=report-{report_detail.id}.pdf"}
    return Response(content=payload, media_type="application/pdf", headers=headers)
