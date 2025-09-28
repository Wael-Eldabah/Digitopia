"""Software-only simulation / demo — no real systems will be contacted or modified."""
from __future__ import annotations

import csv
from io import BytesIO, StringIO
from typing import List

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response, StreamingResponse

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from ..models.schemas import Report, ReportDetail
from ..utils.state import state_store

router = APIRouter(prefix="/api/v1", tags=["reports"])


def _clone_report(report: Report) -> Report:
    return Report(**report.model_dump())


def _build_pdf(report: ReportDetail) -> bytes:
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    text_object = pdf.beginText(40, 750)
    text_object.textLine("EyeGuard Incident Report")
    text_object.textLine("")
    lines = [
        f"Report ID: {report.id}",
        f"Alert ID: {report.alert_id}",
        f"Summary: {report.summary}",
        f"Remediation: {report.remediation_steps or 'N/A'}",
    ]
    text_object.textLine("")
    for line in lines:
        text_object.textLine(line)
    text_object.textLine("")
    text_object.textLine("Indicators:")
    for indicator in report.indicators:
        text_object.textLine(f"- {indicator}")
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
    writer.writerow(["field", "value"])
    writer.writerow(["report_id", report_detail.id])
    writer.writerow(["alert_id", report_detail.alert_id])
    writer.writerow(["summary", report_detail.summary])
    writer.writerow(["remediation", report_detail.remediation_steps or ""])
    writer.writerow(["indicators", ";".join(report_detail.indicators)])
    output.seek(0)
    headers = {"Content-Disposition": f"attachment; filename=report-{report_detail.id}.csv"}
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers=headers)


@router.get("/reports/{report_id}/export.pdf")
async def export_report_pdf(report_id: str) -> Response:
    report_detail = await get_report(report_id)
    payload = _build_pdf(report_detail)
    headers = {"Content-Disposition": f"attachment; filename=report-{report_detail.id}.pdf"}
    return Response(content=payload, media_type="application/pdf", headers=headers)
