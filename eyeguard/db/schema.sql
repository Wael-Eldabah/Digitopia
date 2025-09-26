-- Software-only simulation / demo — no real systems will be contacted or modified.
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT NOT NULL UNIQUE CHECK (email LIKE '%@eyeguard.com'),
    role TEXT NOT NULL CHECK (role IN ('SOC_ANALYST','INCIDENT_RESPONDER','MANAGER')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','disabled')),
    password_hash TEXT NOT NULL,\n    alert_email TEXT,\n    team_alert_emails JSONB DEFAULT '[]'::JSONB,\n    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address INET NOT NULL UNIQUE,
    hostname TEXT NOT NULL,
    device_type TEXT NOT NULL,
    owner_role TEXT NOT NULL CHECK (owner_role IN ('SOC_ANALYST','INCIDENT_RESPONDER','MANAGER','SIM_DEVICE')),
    traffic_gb NUMERIC(12,2) NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'online' CHECK (status IN ('online','degraded','blocked','offline')),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_ip INET NOT NULL,
    destination_ip INET,
    category TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('Low','Medium','High')),
    status TEXT NOT NULL DEFAULT 'Open' CHECK (status IN ('Open','Acknowledged','Resolved')),
    origin_device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    raised_by UUID REFERENCES users(id) ON DELETE SET NULL,
    action_taken TEXT,
    rationale TEXT,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    type TEXT NOT NULL CHECK (type IN ('pcap','indicator')),
    title TEXT NOT NULL,
    has_alerts BOOLEAN NOT NULL DEFAULT FALSE,
    summary JSONB DEFAULT '{}'::JSONB,
    payload JSONB DEFAULT '{}'::JSONB,
    cached BOOLEAN,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reports_user ON reports(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS simulation_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    owner_id UUID REFERENCES users(id) ON DELETE SET NULL,
    command_executed TEXT NOT NULL,
    command_output TEXT,
    session_state JSONB DEFAULT '{}'::JSONB,
    auto_blocked BOOLEAN NOT NULL DEFAULT FALSE,
    traffic_gb NUMERIC(12,2) NOT NULL DEFAULT 0,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS file_snapshots (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id UUID REFERENCES alerts(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('edit','create','delete','move')),
    previous_hash TEXT,
    new_hash TEXT,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ip_reputation (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address INET NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('Low','Medium','High')),
    recommended_action TEXT NOT NULL CHECK (recommended_action IN ('Notify','Monitor','Block')),
    verdict TEXT NOT NULL,
    rationale TEXT,
    recent_alerts JSONB DEFAULT '[]'::JSONB,
    related_devices JSONB DEFAULT '[]'::JSONB,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cached_until TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS virustotal_responses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    reputation_id UUID REFERENCES ip_reputation(id) ON DELETE CASCADE,
    raw_response JSONB NOT NULL,
    malicious_count INTEGER,
    suspicious_count INTEGER,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS otx_responses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    reputation_id UUID REFERENCES ip_reputation(id) ON DELETE CASCADE,
    raw_response JSONB NOT NULL,
    pulse_count INTEGER,
    reference_count INTEGER,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS abuseipdb_responses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    reputation_id UUID REFERENCES ip_reputation(id) ON DELETE CASCADE,
    raw_response JSONB NOT NULL,
    abuse_score INTEGER,
    total_reports INTEGER,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS api_responses_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    lookup_id UUID REFERENCES ip_reputation(id) ON DELETE CASCADE,
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    provider TEXT NOT NULL,
    status_code INTEGER,
    error_message TEXT,
    response_time_ms NUMERIC(12,2),
    logged_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_detected_at ON alerts(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_alert_id ON reports(alert_id);
CREATE INDEX IF NOT EXISTS idx_sim_sessions_device_id ON simulation_sessions(device_id);
CREATE INDEX IF NOT EXISTS idx_file_snapshots_alert_id ON file_snapshots(alert_id);
CREATE INDEX IF NOT EXISTS idx_ip_reputation_ip ON ip_reputation(ip_address);
CREATE INDEX IF NOT EXISTS idx_vt_reputation ON virustotal_responses(reputation_id);
CREATE INDEX IF NOT EXISTS idx_otx_reputation ON otx_responses(reputation_id);
CREATE INDEX IF NOT EXISTS idx_abuse_reputation ON abuseipdb_responses(reputation_id);
CREATE INDEX IF NOT EXISTS idx_api_log_lookup ON api_responses_log(lookup_id);
CREATE INDEX IF NOT EXISTS idx_api_log_provider ON api_responses_log(provider);
\nCREATE TABLE IF NOT EXISTS blocked_ips (\n    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),\n    ip INET NOT NULL UNIQUE,\n    blocked_by UUID REFERENCES users(id) ON DELETE SET NULL,\n    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\n);\n\nCREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip);\n
\nCREATE TABLE IF NOT EXISTS threat_alerts (\n    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),\n    user_id UUID REFERENCES users(id) ON DELETE CASCADE,\n    report_id UUID REFERENCES reports(id) ON DELETE CASCADE,\n    indicator TEXT NOT NULL,\n    severity TEXT NOT NULL CHECK (severity IN ('high','medium','low')),\n    message TEXT NOT NULL,\n    is_read BOOLEAN NOT NULL DEFAULT FALSE,\n    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\n);\n\nCREATE INDEX IF NOT EXISTS idx_threat_alerts_user ON threat_alerts(user_id, is_read);\nCREATE INDEX IF NOT EXISTS idx_threat_alerts_report ON threat_alerts(report_id);\n

\nCREATE TABLE IF NOT EXISTS activity_logs (\n    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),\n    user_id UUID REFERENCES users(id) ON DELETE SET NULL,\n    action TEXT NOT NULL,\n    target TEXT,\n    details JSONB DEFAULT '{}'::JSONB,\n    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\n);\n\nCREATE INDEX IF NOT EXISTS idx_activity_logs_user ON activity_logs(user_id, created_at DESC);\n
