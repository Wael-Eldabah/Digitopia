"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

import smtplib
from email.mime.text import MIMEText
from typing import Iterable, List

from ..config import get_settings
from ..logging_config import logger

settings = get_settings()


def send_alert_email(recipients: Iterable[str], subject: str, body: str) -> None:
    to_addresses: List[str] = [addr for addr in (recipient.strip() for recipient in recipients) if addr]
    if not to_addresses:
        return
    if not settings.smtp_server or not settings.alert_email_from:
        logger.info("email.disabled", reason="SMTP not configured")
        return

    message = MIMEText(body)
    message["Subject"] = subject
    message["From"] = settings.alert_email_from
    message["To"] = ", ".join(to_addresses)

    try:
        with smtplib.SMTP(settings.smtp_server, settings.smtp_port) as client:
            client.starttls()
            if settings.smtp_user and settings.smtp_pass:
                client.login(settings.smtp_user, settings.smtp_pass)
            client.sendmail(settings.alert_email_from, to_addresses, message.as_string())
        logger.info("email.sent", recipients=len(to_addresses))
    except Exception as exc:  # pragma: no cover - network interaction
        logger.warning("email.failed", error=str(exc))
