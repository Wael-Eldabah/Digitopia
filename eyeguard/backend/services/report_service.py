"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..logging_config import logger


async def log_activity(db: AsyncSession, user_id: Optional[str], action: str, target: Optional[str], details: Dict[str, Any]) -> None:
    statement = text(
        """
        INSERT INTO activity_logs (user_id, action, target, details)
        VALUES (:user_id, :action, :target, :details::jsonb)
        """
    )
    await db.execute(
        statement,
        {
            "user_id": user_id,
            "action": action,
            "target": target,
            "details": json.dumps(details),
        },
    )


async def save_report(
    db: AsyncSession,
    *,
    user_id: str,
    report_type: str,
    title: str,
    has_alerts: bool,
    summary: Dict[str, Any],
    payload: Dict[str, Any],
    cached: Optional[bool] = None,
) -> str:
    statement = text(
        """
        INSERT INTO reports (user_id, type, title, has_alerts, summary, payload, cached)
        VALUES (:user_id, :type, :title, :has_alerts, :summary::jsonb, :payload::jsonb, :cached)
        RETURNING id
        """
    )
    result = await db.execute(
        statement,
        {
            "user_id": user_id,
            "type": report_type,
            "title": title,
            "has_alerts": has_alerts,
            "summary": json.dumps(summary),
            "payload": json.dumps(payload),
            "cached": cached,
        },
    )
    report_id = result.scalar_one()
    logger.info("report.created", report_id=report_id, type=report_type, has_alerts=has_alerts)
    return str(report_id)


async def list_reports(db: AsyncSession, user_id: str, limit: int = 20, offset: int = 0) -> List[Dict[str, Any]]:
    statement = text(
        """
        SELECT id, type, title, has_alerts, summary, cached, created_at
        FROM reports
        WHERE user_id = :user_id
        ORDER BY created_at DESC
        LIMIT :limit OFFSET :offset
        """
    )
    result = await db.execute(statement, {"user_id": user_id, "limit": limit, "offset": offset})
    rows: List[Dict[str, Any]] = []
    for record in result:
        rows.append(
            {
                "id": str(record.id),
                "type": record.type,
                "title": record.title,
                "has_alerts": record.has_alerts,
                "summary": record.summary or {},
                "cached": record.cached,
                "created_at": record.created_at.isoformat() if record.created_at else None,
            }
        )
    return rows


async def get_report(db: AsyncSession, user_id: str, report_id: str) -> Optional[Dict[str, Any]]:
    statement = text(
        """
        SELECT id, type, title, has_alerts, summary, payload, cached, created_at
        FROM reports
        WHERE id = :report_id AND user_id = :user_id
        """
    )
    result = await db.execute(statement, {"report_id": report_id, "user_id": user_id})
    record = result.fetchone()
    if not record:
        return None
    return {
        "id": str(record.id),
        "type": record.type,
        "title": record.title,
        "has_alerts": record.has_alerts,
        "summary": record.summary or {},
        "payload": record.payload or {},
        "cached": record.cached,
        "created_at": record.created_at.isoformat() if record.created_at else None,
    }


async def delete_report(db: AsyncSession, user_id: str, report_id: str) -> bool:
    statement = text(
        """DELETE FROM reports WHERE id = :report_id AND user_id = :user_id RETURNING id"""
    )
    result = await db.execute(statement, {"report_id": report_id, "user_id": user_id})
    return result.scalar() is not None


async def create_alerts(
    db: AsyncSession,
    *,
    user_id: str,
    report_id: str,
    indicator_messages: Iterable[Tuple[str, str, str]],
) -> None:
    entries = list(indicator_messages)
    if not entries:
        return
    statement = text(
        """
        INSERT INTO threat_alerts (user_id, report_id, indicator, severity, message)
        VALUES (:user_id, :report_id, :indicator, :severity, :message)
        """
    )
    for indicator, severity, message in entries:
        await db.execute(
            statement,
            {
                "user_id": user_id,
                "report_id": report_id,
                "indicator": indicator,
                "severity": severity,
                "message": message,
            },
        )


async def list_alerts(db: AsyncSession, user_id: str, limit: int = 20, offset: int = 0) -> List[Dict[str, Any]]:
    statement = text(
        """
        SELECT id, report_id, indicator, severity, message, is_read, created_at
        FROM threat_alerts
        WHERE user_id = :user_id
        ORDER BY created_at DESC
        LIMIT :limit OFFSET :offset
        """
    )
    result = await db.execute(statement, {"user_id": user_id, "limit": limit, "offset": offset})
    return [
        {
            "id": str(record.id),
            "report_id": str(record.report_id),
            "indicator": record.indicator,
            "severity": record.severity,
            "message": record.message,
            "is_read": record.is_read,
            "created_at": record.created_at.isoformat() if record.created_at else None,
        }
        for record in result
    ]


async def unread_alert_count(db: AsyncSession, user_id: str) -> int:
    statement = text(
        """SELECT COUNT(1) FROM threat_alerts WHERE user_id = :user_id AND is_read = FALSE"""
    )
    result = await db.execute(statement, {"user_id": user_id})
    return int(result.scalar_one())


async def mark_alert_read(db: AsyncSession, user_id: str, alert_id: str) -> bool:
    statement = text(
        """UPDATE threat_alerts SET is_read = TRUE WHERE id = :alert_id AND user_id = :user_id RETURNING id"""
    )
    result = await db.execute(statement, {"alert_id": alert_id, "user_id": user_id})
    return result.scalar() is not None


async def add_blocked_ip(db: AsyncSession, ip: str, blocked_by: str) -> None:
    statement = text(
        """
        INSERT INTO blocked_ips (ip, blocked_by)
        VALUES (:ip, :blocked_by)
        ON CONFLICT (ip) DO UPDATE SET blocked_by = EXCLUDED.blocked_by, created_at = NOW()
        """
    )
    await db.execute(statement, {"ip": ip, "blocked_by": blocked_by})


async def is_ip_blocked(db: AsyncSession, ip: str) -> bool:
    statement = text("SELECT 1 FROM blocked_ips WHERE ip = :ip LIMIT 1")
    result = await db.execute(statement, {"ip": ip})
    return result.scalar() is not None


async def upsert_user_alert_settings(db: AsyncSession, user_id: str, alert_email: Optional[str], team_alert_emails: Optional[List[str]]) -> None:
    statement = text(
        """
        UPDATE users
        SET alert_email = :alert_email,
            team_alert_emails = COALESCE(:team_alert_emails::jsonb, team_alert_emails)
        WHERE id = :user_id
        """
    )
    await db.execute(
        statement,
        {
            "alert_email": alert_email,
            "team_alert_emails": json.dumps(team_alert_emails) if team_alert_emails is not None else None,
            "user_id": user_id,
        },
    )


async def get_user_alert_settings(db: AsyncSession, user_id: str) -> Dict[str, Any]:
    statement = text("SELECT alert_email, team_alert_emails FROM users WHERE id = :user_id")
    result = await db.execute(statement, {"user_id": user_id})
    record = result.fetchone()
    if not record:
        return {"alert_email": None, "team_alert_emails": []}
    return {
        "alert_email": record.alert_email,
        "team_alert_emails": record.team_alert_emails or [],
    }
