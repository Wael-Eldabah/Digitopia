from pathlib import Path
import textwrap

path = Path(r"c:\Users\WaelAshrafIGRCSQUARE\Desktop\EyeGuard\eyeguard\backend\routes\pcap.py")
text = path.read_text()

helper_anchor = "PCAP_JOB_RETENTION_SECONDS = 180\n\nclass PcapParsingError"
if helper_anchor in text:
    helper_block = "PCAP_JOB_RETENTION_SECONDS = 180\n\nSEVERITY_ORDER = {\"Low\": 1, \"Medium\": 2, \"High\": 3, \"Critical\": 4}\n\n\n" \
        "def normalize_alert_severity(value: Optional[str]) -> str:\n" \
        "    normalized = str(value or \"Low\").title()\n" \
        "    if normalized not in SEVERITY_ORDER:\n" \
        "        normalized = \"Low\"\n" \
        "    return normalized\n\n\n" \
        "def _register_alert(\n" \
        "    alerts: Dict[str, Dict[str, Any]],\n" \
        "    indicator: str,\n" \
        "    *,\n" \
        "    severity: str,\n" \
        "    message: str,\n" \
        "    stats: Optional[Dict[str, Any]] = None,\n" \
        "    **extras: Any,\n" \
        ") -> Dict[str, Any]:\n" \
        "    normalized = normalize_alert_severity(severity)\n" \
        "    payload_stats = {k: v for k, v in (stats or {}).items() if v is not None}\n" \
        "    existing = alerts.get(indicator)\n" \
        "    if existing:\n" \
        "        if SEVERITY_ORDER.get(normalized, 0) > SEVERITY_ORDER.get(existing.get(\"severity\", \"Low\"), 0):\n" \
        "            existing[\"severity\"] = normalized\n" \
        "            existing[\"message\"] = message\n" \
        "        merged_stats = existing.get(\"stats\", {}).copy()\n" \
        "        merged_stats.update(payload_stats)\n" \
        "        existing[\"stats\"] = merged_stats\n" \
        "        for key, value in extras.items():\n" \
        "            if isinstance(existing.get(key), list) and isinstance(value, list):\n" \
        "                for item in value:\n" \
        "                    if item not in existing[key]:\n" \
        "                        existing[key].append(item)\n" \
        "            elif value is not None:\n" \
        "                existing[key] = value\n" \
        "        return existing\n" \
        "    entry: Dict[str, Any] = {\n" \
        "        \"indicator\": indicator,\n" \
        "        \"severity\": normalized,\n" \
        "        \"message\": message,\n" \
        "        \"stats\": payload_stats,\n" \
        "    }\n" \
        "    for key, value in extras.items():\n" \
        "        if value is not None:\n" \
        "            entry[key] = value\n" \
        "    alerts[indicator] = entry\n" \
        "    return entry\n\n\nclass PcapParsingError"
    text = text.replace(helper_anchor, helper_block)

start = text.index("def parse_pcap(")
end = text.index("\n\ndef _ensure_upload_dir")
old_parse = text[start:end]
new_parse = textwrap.dedent(
    """
    def parse_pcap(file_path: str) -> Dict[str, Any]:
        """Parse a PCAP file and return a summary of its contents."""
        try:
            # Validate file header first
            if not validate_pcap_header(file_path):
                raise PcapParsingError("Invalid PCAP/PCAPNG header: incorrect magic number")

            packets = rdpcap(file_path)  # Use scapy to read PCAP/PCAPNG
            total_packets = len(packets)
            unique_ips = set()
            source_ips = set()
            protocol_counts: Dict[str, int] = {}
            ip_packet_counts: Dict[str, int] = {}
            source_packet_counts: Dict[str, int] = {}

            for pkt in packets:
                # Count protocols (simplified, assuming Ethernet + IP)
                if pkt.haslayer(IP):
                    proto = pkt[IP].proto
                    protocol_name = {6: "TCP", 17: "UDP"}.get(proto, f"Protocol_{proto}")
                    protocol_counts[protocol_name] = protocol_counts.get(protocol_name, 0) + 1
                    # Collect IPs
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    unique_ips.add(src_ip)
                    unique_ips.add(dst_ip)
                    source_ips.add(src_ip)
                    ip_packet_counts[src_ip] = ip_packet_counts.get(src_ip, 0) + 1
                    ip_packet_counts[dst_ip] = ip_packet_counts.get(dst_ip, 0) + 1
                    source_packet_counts[src_ip] = source_packet_counts.get(src_ip, 0) + 1

            # Sort IPs by packet count
            top_ips = [
                {"ip": ip, "packet_count": count}
                for ip, count in sorted(ip_packet_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            ]
            top_source_ips = [
                {"ip": ip, "packet_count": count}
                for ip, count in sorted(source_packet_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            ]

            return {
                "total_packets": total_packets,
                "unique_ips": list(unique_ips),
                "source_ips": list(source_ips),
                "top_ips": top_ips,
                "top_source_ips": top_source_ips,
                "protocol_counts": protocol_counts,
            }
        except Exception as e:
            raise PcapParsingError(f"Failed to parse PCAP file: {str(e)}")
    """
).strip("\n")
text = text.replace(old_parse, new_parse)

start = text.index("async def _process_pcap_job")
end = text.index("\n\n\n@router.post(\"/upload\"")
func = text[start:end]

func = func.replace(
    "    summary: Dict[str, Any] = {}\n    ip_payloads: List[Dict[str, Any]] = []\n    alerts_info: List[Dict[str, Any]] = []\n    analysis_errors: List[str] = []\n    critical_candidates: set[str] = set()\n    critical_blocked: List[str] = []\n    alert_indicators: set[str] = set()",
    "    summary: Dict[str, Any] = {}\n    ip_payloads: List[Dict[str, Any]] = []\n    alerts_by_ip: Dict[str, Dict[str, Any]] = {}\n    analysis_errors: List[str] = []\n    critical_candidates: set[str] = set()\n    critical_blocked: List[str] = []",
)

func = func.replace("    malicious_indicators: List[str] = []\n", "")

func = func.replace(
    "    unique_ips = summary.get(\"unique_ips\", [])\n    top_ip_entries = summary.get(\"top_ips\", [])\n    if not top_ip_entries and unique_ips:\n        tentative_limit = max(settings.pcap_enrichment_ip_limit, 0) or 10\n        top_ip_entries = [{\"ip\": ip, \"packet_count\": 0} for ip in unique_ips[:tentative_limit]]\n\n    await _update_pcap_job(\n        job_id,\n        stage=\"enrichment\",\n        message=\"Running threat intelligence enrichment\",\n        progress=30,\n        total_ips=len(unique_ips),\n    )",
    "    source_ips = summary.get(\"source_ips\") or summary.get(\"unique_ips\", [])\n    source_ips = list(dict.fromkeys(source_ips))\n    unique_ips = summary.get(\"unique_ips\", [])\n    if not unique_ips and source_ips:\n        unique_ips = list(source_ips)\n    top_ip_entries = summary.get(\"top_source_ips\") or summary.get(\"top_ips\", [])\n    if not top_ip_entries and source_ips:\n        tentative_limit = max(settings.pcap_enrichment_ip_limit, 0) or 10\n        top_ip_entries = [{\"ip\": ip, \"packet_count\": 0} for ip in source_ips[:tentative_limit]]\n\n    await _update_pcap_job(\n        job_id,\n        stage=\"enrichment\",\n        message=\"Running threat intelligence enrichment\",\n        progress=30,\n        total_ips=len(source_ips),\n    )",
)

func = func.replace(
    "                payload[\"severity\"] = normalized_severity\n                if normalized_severity.lower() == \"critical\":\n                    critical_candidates.add(normalized)\n                payload[\"severity_stats\"] = stats\n                if payload[\"is_malicious\"]:\n                    malicious_indicators.append(normalized)\n                    message = alerting.build_alert_message(normalized, stats)\n                    alerts_info.append(\n                        {\n                            \"indicator\": normalized,\n                            \"severity\": normalized_severity,\n                            \"message\": message,\n                            \"stats\": stats,\n                        }\n                    )\n                    alert_indicators.add(normalized)\n",
    "                normalized_severity = normalize_alert_severity(normalized_severity)\n                payload[\"severity\"] = normalized_severity\n                if normalized_severity == \"Critical\":\n                    critical_candidates.add(normalized)\n                payload[\"severity_stats\"] = stats\n                if payload[\"is_malicious\"]:\n                    message = alerting.build_alert_message(normalized, stats)\n                    registered = _register_alert(\n                        alerts_by_ip,\n                        normalized,\n                        severity=normalized_severity,\n                        message=message,\n                        stats=stats,\n                        source=\"threat_intel\",\n                    )\n                    if payload.get(\"source_results\"):\n                        registered.setdefault(\"source_results\", payload[\"source_results\"])\n                    registered.setdefault(\"malicious_sources\", malicious_sources)\n",
)

func = func.replace(
    "    model_result = adaptive_pcap_model.analyze(summary, ip_payloads)\n    model_insights = model_result.to_dict()\n    severity_order = {\"Info\": 0, \"Low\": 1, \"Medium\": 2, \"High\": 3, \"Critical\": 4}\n    global_severity = model_insights.get(\"severity\", \"Info\")\n\n    for payload in ip_payloads:\n        current = payload.get(\"severity\", \"Info\")\n        if severity_order.get(global_severity, 0) > severity_order.get(str(current).title(), 0):\n            payload[\"severity\"] = global_severity\n        if payload.get(\"ip\") in model_insights.get(\"highlight_indicators\", []):\n            payload.setdefault(\"flags\", []).append(\"model-highlight\")\n            payload.setdefault(\"model_comments\", []).append(\n                f\"Model flagged {payload['ip']} as part of {model_insights.get('attack_type', 'an attack')}\"\n            )\n        if str(payload.get(\"severity\", \"\")).lower() == \"critical\" and payload.get(\"ip\"):\n            critical_candidates.add(payload[\"ip\"])\n\n    for alert in alerts_info:\n        current = str(alert.get(\"severity\", \"Info\")).title()\n        if severity_order.get(global_severity, 0) > severity_order.get(current, 0):\n            alert[\"severity\"] = global_severity\n        alert.setdefault(\"model_severity\", global_severity)\n\n    if model_insights.get(\"severity\") in {\"High\", \"Critical\"} and model_insights.get(\"highlight_indicators\"):\n        for indicator in model_insights[\"highlight_indicators\"][:2]:\n            if indicator in malicious_indicators:\n                continue\n            alerts_info.append(\n                {\n                    \"indicator\": indicator,\n                    \"severity\": model_insights[\"severity\"],\n                    \"message\": f\"Model detected {model_insights['attack_type'].lower()} pattern involving {indicator}.\",\n                    \"model_generated\": True,\n                    \"stats\": {\n                        \"model_risk_score\": model_insights.get(\"risk_score\"),\n                        \"confidence\": model_insights.get(\"confidence\"),\n                    },\n                }\n            )\n            malicious_indicators.append(indicator)\n            alert_indicators.add(indicator)\n\n",
    "    model_result = adaptive_pcap_model.analyze(summary, ip_payloads)\n    model_insights = model_result.to_dict()\n    global_severity = normalize_alert_severity(model_insights.get(\"severity\"))\n\n    highlight_candidates = set(model_insights.get(\"highlight_indicators\") or [])\n\n    for payload in ip_payloads:\n        current = normalize_alert_severity(payload.get(\"severity\"))\n        if SEVERITY_ORDER.get(global_severity, 0) > SEVERITY_ORDER.get(current, 0):\n            payload[\"severity\"] = global_severity\n        indicator = payload.get(\"ip\")\n        if indicator in highlight_candidates:\n            payload.setdefault(\"flags\", []).append(\"model-highlight\")\n            payload.setdefault(\"model_comments\", []).append(\n                f\"Model flagged {payload['ip']} as part of {model_insights.get('attack_type', 'an attack')}\"\n            )\n        normalized_payload_severity = normalize_alert_severity(payload.get(\"severity\"))\n        if indicator and normalized_payload_severity == \"Critical\":\n            critical_candidates.add(indicator)\n        if indicator and indicator in alerts_by_ip:\n            existing_message = alerts_by_ip[indicator].get(\"message\") or alerting.build_alert_message(\n                indicator, payload.get(\"severity_stats\") or {}\n            )\n            _register_alert(\n                alerts_by_ip,\n                indicator,\n                severity=normalized_payload_severity,\n                message=existing_message,\n                stats=payload.get(\"severity_stats\"),\n            )\n\n    highlight_severity = normalize_alert_severity(model_insights.get(\"severity\"))\n    if highlight_candidates and highlight_severity in {\"High\", \"Critical\"}:\n        for indicator in list(highlight_candidates)[:2]:\n            try:\n                normalized_indicator = normalize_ip(indicator)\n            except ValueError:\n                normalized_indicator = indicator\n            message = f\"Model detected {model_insights['attack_type'].lower()} pattern involving {normalized_indicator}.\"\n            entry_stats = {\n                \"model_risk_score\": model_insights.get(\"risk_score\"),\n                \"confidence\": model_insights.get(\"confidence\"),\n            }\n            _register_alert(\n                alerts_by_ip,\n                normalized_indicator,\n                severity=highlight_severity,\n                message=message,\n                stats=entry_stats,\n                model_generated=True,\n            )\n            if highlight_severity == \"Critical\":\n                critical_candidates.add(normalized_indicator)\n\n",
)

func = func.replace(
    "    if critical_candidates:\n        async with state_store._lock:  # type: ignore[attr-defined]\n            for ip_value in sorted(critical_candidates):\n                if not state_store.is_ip_blocked(ip_value):\n                    state_store.add_blocked_ip(ip_value, current_user.id)\n                    critical_blocked.append(ip_value)\n    if critical_blocked:\n        for ip_value in critical_blocked:\n            if ip_value not in alert_indicators:\n                alerts_info.append(\n                    {\n                        \"indicator\": ip_value,\n                        \"severity\": \"Critical\",\n                        \"message\": \"Auto-blocked due to critical PCAP verdict.\",\n                        \"auto_blocked\": True,\n                        \"stats\": {\"auto_block\": True},\n                    }\n                )\n                malicious_indicators.append(ip_value)\n                alert_indicators.add(ip_value)\n        try:\n            async with SessionLocal() as session:\n                for ip_value in critical_blocked:\n                    await report_service.add_blocked_ip(session, ip_value, current_user.id)\n                await session.commit()\n        except Exception as exc:  # pragma: no cover - defensive\n            logger.warning(\"pcap.auto_block.persist_failed\", error=str(exc))\n        await _update_pcap_job(\n            job_id,\n            stage=\"blocklist\",\n            message=f\"Blocking {len(critical_blocked)} critical indicators\",\n            blocked_ips=critical_blocked,\n            progress=95,\n        )\n\n    analysis_errors = list(dict.fromkeys(analysis_errors))\n    malicious_count = len(alert_indicators)\n    has_alerts = bool(alert_indicators)\n    report_summary = {",
    "    newly_blocked: List[str] = []\n    if critical_candidates:\n        async with state_store._lock:  # type: ignore[attr-defined]\n            for ip_value in sorted(critical_candidates):\n                if not state_store.is_ip_blocked(ip_value):\n                    state_store.add_blocked_ip(ip_value, current_user.id)\n                    newly_blocked.append(ip_value)\n    if newly_blocked:\n        critical_blocked.extend(newly_blocked)\n    if critical_blocked:\n        critical_blocked = sorted(set(critical_blocked))\n        for ip_value in critical_blocked:\n            _register_alert(\n                alerts_by_ip,\n                ip_value,\n                severity=\"Critical\",\n                message=\"Auto-blocked due to critical PCAP verdict.\",\n                stats={\"auto_block\": True},\n                auto_blocked=True,\n            )\n        try:\n            async with SessionLocal() as session:\n                for ip_value in newly_blocked:\n                    await report_service.add_blocked_ip(session, ip_value, current_user.id)\n                await session.commit()\n        except Exception as exc:  # pragma: no cover - defensive\n            logger.warning(\"pcap.auto_block.persist_failed\", error=str(exc))\n        await _update_pcap_job(\n            job_id,\n            stage=\"blocklist\",\n            message=f\"Blocking {len(newly_blocked)} critical indicators\" if newly_blocked else \"Blocklist already up to date\",\n            blocked_ips=critical_blocked,\n            progress=95,\n        )\n\n    analysis_errors = list(dict.fromkeys(analysis_errors))\n    alerts_info_list = [{**entry, \"stats\": entry.get(\"stats\", {})} for entry in alerts_by_ip.values()]\n    alerts_info = sorted(\n        alerts_info_list,\n        key=lambda entry: (-SEVERITY_ORDER.get(entry.get(\"severity\", \"Low\"), 0), entry.get(\"indicator\", \"\")),\n    )\n    malicious_count = len(alerts_info)\n    malicious_indicators = [entry[\"indicator\"] for entry in alerts_info]\n    has_alerts = bool(alerts_info)\n    blocked_ip_list = list(critical_blocked) if critical_blocked else []\n    report_summary = {",
)

func = func.replace(
    "        \"description\": f\"PCAP {safe_name} processed\",\n        \"total_packets\": summary.get(\"total_packets\", 0),\n        \"unique_ips\": len(summary.get(\"unique_ips\", [])),\n        \"malicious_ips\": malicious_count,\n        \"protocol_counts\": summary.get(\"protocol_counts\", {}),\n",
    "        \"description\": f\"PCAP {safe_name} processed\",\n        \"total_packets\": summary.get(\"total_packets\", 0),\n        \"unique_ips\": len(unique_ips),\n        \"unique_source_ips\": len(source_ips),\n        \"malicious_ips\": malicious_count,\n        \"malicious_source_ips\": malicious_indicators,\n        \"blocked_ip_count\": len(blocked_ip_list),\n        \"protocol_counts\": summary.get(\"protocol_counts\", {}),\n",
)

func = func.replace(
    "        \"model_insights\": model_insights,\n        \"errors\": analysis_errors,\n        \"blocked_ips\": critical_blocked,\n    }\n\n    await _update_pcap_job(job_id, stage=\"persistence\", message=\"Finalizing analysis results\", progress=90)\n\n    async with state_store._lock:  # type: ignore[attr-defined]\n        state_store.save_pcap_analysis(analysis_record)\n",
    "        \"model_insights\": model_insights,\n        \"errors\": analysis_errors,\n        \"blocked_ips\": blocked_ip_list,\n        \"malicious_indicators\": malicious_indicators,\n    }\n\n    await _update_pcap_job(job_id, stage=\"persistence\", message=\"Finalizing analysis results\", progress=90)\n\n    async with state_store._lock:  # type: ignore[attr-defined]\n        state_store.save_pcap_analysis(analysis_record)\n",
)

func = func.replace(
    "        state_store.log_activity(\n            actor=current_user.id,\n            event=\"pcap.uploaded\",\n            metadata={\n                \"report_id\": report_id,\n                \"file\": safe_name,\n                \"total_packets\": summary.get(\"total_packets\", 0),\n                \"unique_ips\": len(summary.get(\"unique_ips\", [])),\n                \"malicious_ips\": malicious_count,\n            },\n        )\n\n    if has_alerts:\n",
    "        state_store.log_activity(\n            actor=current_user.id,\n            event=\"pcap.uploaded\",\n            metadata={\n                \"report_id\": report_id,\n                \"file\": safe_name,\n                \"total_packets\": summary.get(\"total_packets\", 0),\n                \"unique_source_ips\": len(source_ips),\n                \"malicious_ips\": malicious_count,\n                \"malicious_source_ips\": malicious_indicators,\n                \"blocked_ips\": blocked_ip_list,\n                \"blocked_ip_count\": len(blocked_ip_list),\n            },\n        )\n\n    if has_alerts:\n",
)

func = func.replace(
    "        await _update_pcap_job(\n        job_id,\n        status=\"completed\",\n        stage=\"completed\",\n        message=\"Analysis complete\",\n        progress=100,\n        report_ref=report_id,\n        alerts_generated=malicious_count,\n        blocked_ips=critical_blocked,\n    )\n",
    "        await _update_pcap_job(\n        job_id,\n        status=\"completed\",\n        stage=\"completed\",\n        message=\"Analysis complete\",\n        progress=100,\n        report_ref=report_id,\n        alerts_generated=malicious_count,\n        blocked_ips=blocked_ip_list,\n    )\n",
)

text = text[:start] + func + text[end:]

path.write_text(text)
