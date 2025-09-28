-- Software-only simulation / demo - no real systems will be contacted or modified.
-- Up
BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'alert_email'
    ) THEN
        ALTER TABLE users ADD COLUMN alert_email TEXT;
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'team_alert_emails'
    ) THEN
        ALTER TABLE users ADD COLUMN team_alert_emails JSONB DEFAULT '[]'::JSONB;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    report_ref TEXT UNIQUE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    type TEXT NOT NULL CHECK (type IN ('pcap','indicator')),
    title TEXT NOT NULL,
    source_filename TEXT,
    has_alerts BOOLEAN NOT NULL DEFAULT FALSE,
    summary JSONB DEFAULT '{}'::JSONB,
    payload JSONB DEFAULT '{}'::JSONB,
    cached BOOLEAN,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'reports' AND column_name = 'report_ref'
    ) THEN
        ALTER TABLE reports ADD COLUMN report_ref TEXT UNIQUE;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_reports_user ON reports(user_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_reports_report_ref ON reports(report_ref);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip INET NOT NULL UNIQUE,
    blocked_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip);

CREATE TABLE IF NOT EXISTS threat_alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    report_id UUID REFERENCES reports(id) ON DELETE CASCADE,
    indicator TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('high','medium','low')),
    message TEXT NOT NULL,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_alerts_user ON threat_alerts(user_id, is_read);
CREATE INDEX IF NOT EXISTS idx_threat_alerts_report ON threat_alerts(report_id);

CREATE TABLE IF NOT EXISTS activity_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target TEXT,
    details JSONB DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_activity_logs_user ON activity_logs(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS simulation_state (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    state JSONB NOT NULL DEFAULT '{}'::JSONB,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMIT;

-- Down (safe no-op: structure retained intentionally)
-- To revert manually, drop the created columns/tables if required.
