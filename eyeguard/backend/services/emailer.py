"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

import smtplib
from email.mime.text import MIMEText
from typing import Iterable, List

from ..config import get_settings
from ..logging_config import logger

settings = get_settings()


def send_alert_email(recipients: Iterable[str], subject: str, body: str) -> None:
    addresses: List[str] = [addr.strip() for addr in recipients if addr and addr.strip()]
    if not addresses:
        return
    if not settings.smtp_server or not settings.alert_email_from:
        logger.info("smtp.disabled", reason="missing configuration")
        return

    message = MIMEText(body)
    message["Subject"] = subject
    message["From"] = settings.alert_email_from
    message["To"] = ", ".join(addresses)

    try:
        with smtplib.SMTP(settings.smtp_server, settings.smtp_port, timeout=10) as client:
            try:
                client.starttls()
            except Exception:  # pragma: no cover - optional capability
                logger.debug("smtp.no_tls")
            if settings.smtp_user and settings.smtp_pass:
                client.login(settings.smtp_user, settings.smtp_pass)
            client.sendmail(settings.alert_email_from, addresses, message.as_string())
        logger.info("smtp.sent", count=len(addresses))
    except Exception as exc:  # pragma: no cover - network operation
        logger.warning("smtp.send_failed", error=str(exc))
