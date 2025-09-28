"""Software-only simulation / demo - no real systems will be contacted or modified."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple

from . import emailer
from ..models.schemas import Alert



ALERT_GUIDANCE: Dict[str, Dict[str, Any]] = {
    "Suspicious Connection": {
        "playbook": "Investigate suspicious outbound connection",
        "intel_summary": "Connection triggered egress anomaly heuristics and matched a monitored destination.",
        "actions": [
            "Review firewall and proxy logs for the source host in the same time window.",
            "Correlate host authentication history to confirm the user and workstation context.",
            "Capture endpoint process list and inspect unusual binaries initiating network egress.",
        ],
        "mitigation": [
            "Apply a temporary egress block to the destination IP or domain.",
            "Quarantine the endpoint if malware is suspected and initiate full malware response procedures.",
        ],
        "overrides": {
            "high": {
                "actions": [
                    "Engage the incident response on-call lead and document an active case in the ticketing system.",
                ],
                "mitigation": [
                    "Force credential resets for accounts observed in the session if compromise is suspected.",
                ],
            }
        },
    },
    "PCAP Malicious IP": {
        "playbook": "Respond to malicious network indicators discovered in packet capture",
        "intel_summary": "Threat intelligence confirmed malicious reputation for traffic found in uploaded capture.",
        "actions": [
            "Pivot to the original capture to isolate conversations involving the malicious IP.",
            "Validate whether the IP exists in blocklists and update firewall rules if required.",
            "Notify affected service owners about potential compromise of involved assets.",
        ],
        "mitigation": [
            "Block the IP at perimeter firewalls and update intrusion prevention signatures.",
            "Trigger endpoint containment for devices observed communicating with the indicator.",
        ],
    },
    "Threat Intel Verdict": {
        "playbook": "Respond to adverse threat intelligence verdict",
        "intel_summary": "Automated verdict from aggregated threat intelligence feeds indicated a malicious rating.",
        "actions": [
            "Review detailed provider telemetry (VirusTotal, OTX, AbuseIPDB) for supporting context.",
            "Investigate recent device activity involving the indicator across SIEM and EDR logs.",
        ],
        "mitigation": [
            "Ensure the indicator is blocked at the gateway and proxy tiers.",
            "Schedule a threat-hunt task to look for similar indicators within the environment.",
        ],
        "overrides": {
            "high": {
                "actions": [
                    "Open an incident record and begin formal response workflow (IR-110).",
                ],
                "mitigation": [
                    "Disconnect the affected asset from corporate network until forensic triage is complete.",
                ],
            },
            "medium": {
                "actions": [
                    "Increase telemetry collection from the device (EDR live response, memory snapshot).",
                ],
            },
        },
    },
    "Blocklist Enforcement": {
        "playbook": "Blocklist enforcement response",
        "intel_summary": "A session attempted to use an IP present on the enforced blocklist.",
        "actions": [
            "Validate that the blocklist entry is still required and not a false positive.",
            "Check for repeated access attempts to confirm whether automation is required.",
        ],
        "mitigation": [
            "Update the blocklist description with investigation notes for future analysts.",
            "Communicate the block with service owners if the asset belongs to production infrastructure.",
        ],
    },
    "Traffic Spike": {
        "playbook": "Investigate unexpected network volume spike",
        "intel_summary": "Observed throughput exceeded the defined threshold for the monitored device.",
        "actions": [
            "Correlate with NetFlow or firewall logs to identify the top talkers and destinations.",
            "Confirm with the system owner whether a planned activity (backup, deployment) was running.",
        ],
        "mitigation": [
            "Throttle or rate-limit the interface if throughput threatens capacity.",
            "Enable additional monitoring or alerts for recurring spikes.",
        ],
    },
    "Restricted Access": {
        "playbook": "Respond to unauthorized access of restricted directories",
        "intel_summary": "Simulation user attempted to access a sensitive path requiring elevated privileges.",
        "actions": [
            "Review command history to determine the intent of the user or process.",
            "Verify the account permissions and ensure least-privilege policies are enforced.",
        ],
        "mitigation": [
            "Tighten directory permissions or ACLs to prevent recurring unauthorized access.",
            "Enable additional auditing on the sensitive directory to capture follow-on attempts.",
        ],
    },
    "File Modification": {
        "playbook": "Investigate unexpected file modification",
        "intel_summary": "File contents were modified outside of approved change workflows.",
        "actions": [
            "Compare the new file hash with baseline and retrieve prior versions from backup.",
            "Identify the process or user performing the modification via audit logs.",
        ],
        "mitigation": [
            "Restore validated baseline content and monitor file integrity with FIM tooling.",
            "Implement stricter change controls or code signing for the file path.",
        ],
    },
    "File Removal": {
        "playbook": "Investigate unauthorized file deletion",
        "intel_summary": "A monitored file was removed from the host, potentially indicating tampering.",
        "actions": [
            "Determine whether the removal was part of a maintenance task by contacting the asset owner.",
            "Review security telemetry for signs of malware or attacker tradecraft around the deletion time.",
        ],
        "mitigation": [
            "Restore the file from clean backup media.",
            "Harden file system permissions and enable alerts for subsequent deletions of critical assets.",
        ],
    },
}

DEFAULT_GUIDANCE = {
    "playbook": "Triage and document alert response",
    "intel_summary": "Gather context, validate authenticity, and determine containment requirements for the alert.",
    "actions": [
        "Validate the alert in the SIEM or source system to confirm it is not a false positive.",
        "Collect relevant telemetry (logs, endpoint data) to enrich investigation notes.",
    ],
    "mitigation": [
        "Document findings and escalate according to the incident handling policy if the alert is confirmed.",
    ],
}




def _merge_unique(primary: list[str] | None, fallback: list[str] | None) -> list[str]:
    values: list[str] = []
    for source in (primary or []):
        if source not in values:
            values.append(source)
    for item in fallback or []:
        if item not in values:
            values.append(item)
    return values


def apply_alert_guidance(alert: Alert) -> Alert:
    guidance = build_alert_guidance(alert.category, alert.severity)
    payload = alert.model_dump()
    payload.setdefault('playbook', guidance.get('playbook'))
    payload.setdefault('intel_summary', guidance.get('intel_summary'))
    payload['recommended_actions'] = _merge_unique(payload.get('recommended_actions'), guidance.get('recommended_actions'))
    payload['mitigation_steps'] = _merge_unique(payload.get('mitigation_steps'), guidance.get('mitigation_steps'))
    return Alert(**payload)

def build_alert_guidance(category: str, severity: str) -> Dict[str, List[str] | str | None]:
    entry = ALERT_GUIDANCE.get(category, DEFAULT_GUIDANCE)
    severity_key = severity.lower() if severity else ""
    overrides = entry.get("overrides", {})

    actions = list(entry.get("actions", []))
    mitigation = list(entry.get("mitigation", []))

    if severity_key in overrides:
        spec = overrides[severity_key]
        actions.extend(spec.get("actions", []))
        mitigation.extend(spec.get("mitigation", []))

    return {
        "playbook": entry.get("playbook"),
        "intel_summary": entry.get("intel_summary"),
        "recommended_actions": actions,
        "mitigation_steps": mitigation,
    }

def severity_from_sources(source_results: Dict[str, Dict[str, Dict[str, int]]]) -> Tuple[str, Dict[str, int]]:
    vt_data = source_results.get("virustotal", {}).get("data", {})
    otx_data = source_results.get("otx", {}).get("data", {})
    abuse_data = source_results.get("abuseipdb", {}).get("data", {})

    vt_malicious = vt_data.get("malicious_count", 0)
    otx_pulses = otx_data.get("pulse_count", 0)
    abuse_score = abuse_data.get("abuse_score", 0)

    if abuse_score >= 80 or vt_malicious >= 3:
        level = "high"
    elif vt_malicious >= 1 or otx_pulses >= 1 or abuse_score >= 50:
        level = "medium"
    else:
        level = "low"
    return level, {
        "vt_malicious": vt_malicious,
        "otx_pulses": otx_pulses,
        "abuse_score": abuse_score,
    }


def build_alert_message(indicator: str, stats: Dict[str, int]) -> str:
    parts: List[str] = []
    if stats.get("vt_malicious"):
        parts.append(f"VT={stats['vt_malicious']}")
    if stats.get("otx_pulses"):
        parts.append(f"OTX={stats['otx_pulses']}")
    if stats.get("abuse_score"):
        parts.append(f"Abuse={stats['abuse_score']}")
    detail = ", ".join(parts) if parts else "No high confidence telemetry"
    return f"Malicious indicator detected: {indicator} ({detail})"


def dispatch_alert_email(recipients: Iterable[str], indicator: str, severity: str, message: str) -> None:
    subject = f"EyeGuard Alert ({severity.title()}): {indicator}"
    body = f"Severity: {severity}\nIndicator: {indicator}\nDetails: {message}\n"
    emailer.send_alert_email(recipients, subject, body)
