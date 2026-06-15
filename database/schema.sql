CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE TABLE IF NOT EXISTS events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  event_id INT,
  provider TEXT,
  hostname TEXT,
  username TEXT,
  process TEXT,
  command_line TEXT,
  source_ip TEXT,
  source_port INT,
  destination_ip TEXT,
  destination_port INT,
  protocol TEXT,
  file_path TEXT,
  raw JSONB NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);
ALTER TABLE events ADD COLUMN IF NOT EXISTS source_port INT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS destination_ip TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS destination_port INT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS protocol TEXT;
CREATE TABLE IF NOT EXISTS alerts (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  event_ref UUID REFERENCES events(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT DEFAULT 'new',
  hostname TEXT,
  username TEXT,
  process TEXT,
  source_ip TEXT,
  file_path TEXT,
  email_sender TEXT,
  email_recipient TEXT,
  email_subject TEXT,
  email_score INT,
  matched_term TEXT,
  mitre TEXT,
  recommendation TEXT,
  evidence JSONB,
  created_at TIMESTAMPTZ DEFAULT now()
);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS file_path TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS email_sender TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS email_recipient TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS email_subject TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS email_score INT;
CREATE TABLE IF NOT EXISTS incidents (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT DEFAULT 'open',
  summary TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id);
CREATE INDEX IF NOT EXISTS idx_events_hostname ON events(hostname);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_destination_port ON events(destination_port);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE TABLE IF NOT EXISTS incident_alerts (incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE, alert_id UUID REFERENCES alerts(id) ON DELETE CASCADE, PRIMARY KEY(incident_id, alert_id));
CREATE TABLE IF NOT EXISTS actions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
  action_type TEXT NOT NULL,
  target TEXT NOT NULL,
  status TEXT DEFAULT 'requested',
  output TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS blocked_ips (
  ip TEXT PRIMARY KEY,
  reason TEXT,
  status TEXT DEFAULT 'blocked',
  last_action_id UUID REFERENCES actions(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS email_threats (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  event_ref UUID REFERENCES events(id) ON DELETE CASCADE,
  sender TEXT,
  recipient TEXT,
  subject TEXT,
  severity TEXT,
  score INT DEFAULT 0,
  indicators JSONB,
  urls JSONB,
  attachments JSONB,
  raw JSONB,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_email_threats_created_at ON email_threats(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_threats_severity ON email_threats(severity);
CREATE TABLE IF NOT EXISTS ip_intel (
  ip TEXT PRIMARY KEY,
  country TEXT,
  city TEXT,
  latitude DOUBLE PRECISION,
  longitude DOUBLE PRECISION,
  asn TEXT,
  isp TEXT,
  reputation_score INT DEFAULT 0,
  abuse_confidence INT,
  total_reports INT,
  source TEXT DEFAULT 'local',
  raw JSONB,
  updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ip_intel_updated_at ON ip_intel(updated_at DESC);
