BEGIN TRANSACTION;
CREATE TABLE build_log (
  key TEXT PRIMARY KEY,
  value TEXT
);
CREATE TABLE dns_validations (
  event_id TEXT PRIMARY KEY,
  hostname TEXT NOT NULL,
  dns_state TEXT,
  active_eligibility TEXT,
  parent_zone TEXT,
  observed_at TEXT,
  data TEXT
);
INSERT INTO "dns_validations" VALUES('e-dns-validation','app.example.test','resolved','eligible','example.test','2026-01-05T00:00:00Z','{"active_eligibility":"eligible","dns_state":"resolved","parent_zone":"example.test"}');
CREATE TABLE events (
  event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  module TEXT NOT NULL,
  source_tool TEXT,
  observed_at TEXT,
  raw_value TEXT,
  normalized_value TEXT,
  scope_status TEXT,
  confidence REAL,
  evidence TEXT,
  relations TEXT,
  metadata TEXT
);
INSERT INTO "events" VALUES('e-domain-1','subdomain_found','fixture','collector-a','2026-01-01T00:00:00Z','"app.example.test"','"app.example.test"','in_scope',0.3,'{}','[{"evidence":{"x":1},"relation_type":"resolves_to","source_id":"domain:app.example.test","target_id":"ip:192.0.2.10"}]','{"collector_tool":"collector-a","evidence_family":"certificate_transparency","first_seen_by_provider":"2025-01-01","provider":"ct.example"}');
INSERT INTO "events" VALUES('e-domain-2','subdomain_found','fixture','collector-b','2026-01-02T00:00:00Z','"app.example.test"','"app.example.test"','out_of_scope',0.9,'{}','[{"evidence":{"x":2},"relation_type":"resolves_to","source_id":"domain:app.example.test","target_id":"ip:192.0.2.10"}]','{"collector_tool":"collector-b","evidence_family":"certificate_transparency","provider":"ct.example"}');
INSERT INTO "events" VALUES('e-shot','screenshot_saved','fixture','fixture-source','2026-01-03T00:00:00Z','"https://app.example.test/"','"https://app.example.test/"','in_scope',0.5,'{}','[]','{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","target_domain":"example.test","url":"https://app.example.test/"}');
INSERT INTO "events" VALUES('e-shot-fallback','screenshot_saved','fixture','fixture-source','2026-01-03T00:00:00Z','"https://fallback.example.test/"','"https://fallback.example.test/"','in_scope',0.5,'{}','[]','{"sha256":"","target_domain":"example.test","url":""}');
INSERT INTO "events" VALUES('e-health','source_health','fixture','fallback-tool','2026-01-04T00:00:00Z','"ok"','"ok"','in_scope',0.5,'{}','[]','{"collector":"collector-a","provider":"ct.example","role":"primary","status":"ok"}');
INSERT INTO "events" VALUES('e-health-empty','source_health','fixture','fallback-tool','2026-01-04T00:00:00Z','"ok"','"ok"','in_scope',0.5,'{}','[]','{"collector":"","provider":"","role":"","status":""}');
INSERT INTO "events" VALUES('e-provider-empty','subdomain_found','fixture','fixture-source','2026-01-04T00:00:00Z','"empty-provider.example.test"','"empty-provider.example.test"','in_scope',0.5,'{}','[]','{"provider":""}');
INSERT INTO "events" VALUES('e-dns-validation','dns_validation','fixture','fixture-source','2026-01-05T00:00:00Z','"app.example.test"','"app.example.test"','in_scope',0.5,'{}','[]','{"active_eligibility":"eligible","dns_state":"resolved","parent_zone":"example.test"}');
INSERT INTO "events" VALUES('e-limit','limitation','fixture','fixture-source','2026-01-06T00:00:00Z','"budget"','"budget"','in_scope',0.5,'{}','[]','{}');
CREATE TABLE limitations (
  limitation_id TEXT PRIMARY KEY,
  observed_at TEXT,
  reason TEXT,
  data TEXT
);
INSERT INTO "limitations" VALUES('e-limit','2026-01-06T00:00:00Z','budget','{"confidence":0.5,"event_id":"e-limit","event_type":"limitation","evidence":{},"metadata":{},"module":"fixture","normalized_value":"budget","observed_at":"2026-01-06T00:00:00Z","raw_value":"budget","relations":[],"scope_status":"in_scope","source_tool":"fixture-source"}');
CREATE TABLE objects (
  object_id TEXT PRIMARY KEY,
  object_type TEXT NOT NULL,
  value TEXT NOT NULL,
  first_seen TEXT,
  last_seen TEXT,
  sources TEXT NOT NULL DEFAULT '[]',
  scope_status TEXT,
  confidence REAL,
  data TEXT NOT NULL DEFAULT '{}'
);
INSERT INTO "objects" VALUES('domain:app.example.test','domain','app.example.test','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z','["collector-a","collector-b"]','out_of_scope',0.9,'{"events":["e-domain-1","e-domain-2"],"latest":{"confidence":0.9,"event_id":"e-domain-2","event_type":"subdomain_found","evidence":{},"metadata":{"collector_tool":"collector-b","evidence_family":"certificate_transparency","provider":"ct.example"},"module":"fixture","normalized_value":"app.example.test","observed_at":"2026-01-02T00:00:00Z","raw_value":"app.example.test","relations":[{"evidence":{"x":2},"relation_type":"resolves_to","source_id":"domain:app.example.test","target_id":"ip:192.0.2.10"}],"scope_status":"out_of_scope","source_tool":"collector-b"}}');
INSERT INTO "objects" VALUES('screenshot:31bdc048bfce3867:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','screenshot','31bdc048bfce3867:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','2026-01-03T00:00:00Z','2026-01-03T00:00:00Z','["fixture-source"]','in_scope',0.5,'{"events":["e-shot"],"latest":{"confidence":0.5,"event_id":"e-shot","event_type":"screenshot_saved","evidence":{},"metadata":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","target_domain":"example.test","url":"https://app.example.test/"},"module":"fixture","normalized_value":"https://app.example.test/","observed_at":"2026-01-03T00:00:00Z","raw_value":"https://app.example.test/","relations":[],"scope_status":"in_scope","source_tool":"fixture-source"}}');
INSERT INTO "objects" VALUES('screenshot:4a00e21b2ca8f507:https://fallback.example.test/','screenshot','4a00e21b2ca8f507:https://fallback.example.test/','2026-01-03T00:00:00Z','2026-01-03T00:00:00Z','["fixture-source"]','in_scope',0.5,'{"events":["e-shot-fallback"],"latest":{"confidence":0.5,"event_id":"e-shot-fallback","event_type":"screenshot_saved","evidence":{},"metadata":{"sha256":"","target_domain":"example.test","url":""},"module":"fixture","normalized_value":"https://fallback.example.test/","observed_at":"2026-01-03T00:00:00Z","raw_value":"https://fallback.example.test/","relations":[],"scope_status":"in_scope","source_tool":"fixture-source"}}');
INSERT INTO "objects" VALUES('domain:empty-provider.example.test','domain','empty-provider.example.test','2026-01-04T00:00:00Z','2026-01-04T00:00:00Z','["fixture-source"]','in_scope',0.5,'{"events":["e-provider-empty"],"latest":{"confidence":0.5,"event_id":"e-provider-empty","event_type":"subdomain_found","evidence":{},"metadata":{"provider":""},"module":"fixture","normalized_value":"empty-provider.example.test","observed_at":"2026-01-04T00:00:00Z","raw_value":"empty-provider.example.test","relations":[],"scope_status":"in_scope","source_tool":"fixture-source"}}');
CREATE TABLE provider_health (
  event_id TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  collector TEXT,
  role TEXT,
  status TEXT,
  observed_at TEXT,
  data TEXT
);
INSERT INTO "provider_health" VALUES('e-health','ct.example','collector-a','primary','ok','2026-01-04T00:00:00Z','{"collector":"collector-a","provider":"ct.example","role":"primary","status":"ok"}');
INSERT INTO "provider_health" VALUES('e-health-empty','fallback-tool','','','','2026-01-04T00:00:00Z','{"collector":"","provider":"","role":"","status":""}');
CREATE TABLE provider_observations (
  event_id TEXT PRIMARY KEY,
  hostname TEXT NOT NULL,
  provider TEXT NOT NULL,
  collector TEXT,
  evidence_family TEXT,
  first_seen_by_provider TEXT,
  observed_at TEXT,
  scope_status TEXT,
  metadata TEXT
);
INSERT INTO "provider_observations" VALUES('e-domain-1','app.example.test','ct.example','collector-a','certificate_transparency','2025-01-01','2026-01-01T00:00:00Z','in_scope','{"collector_tool":"collector-a","evidence_family":"certificate_transparency","first_seen_by_provider":"2025-01-01","provider":"ct.example"}');
INSERT INTO "provider_observations" VALUES('e-domain-2','app.example.test','ct.example','collector-b','certificate_transparency',NULL,'2026-01-02T00:00:00Z','out_of_scope','{"collector_tool":"collector-b","evidence_family":"certificate_transparency","provider":"ct.example"}');
CREATE TABLE relations (
  relation_id TEXT PRIMARY KEY,
  source_id TEXT,
  target_id TEXT,
  relation_type TEXT,
  evidence TEXT
);
INSERT INTO "relations" VALUES('rel:ba4cd710a393647f253533d9','domain:app.example.test','ip:192.0.2.10','resolves_to','{"x":2}');
CREATE INDEX idx_events_event_type ON events(event_type);
CREATE INDEX idx_events_source_tool ON events(source_tool);
CREATE INDEX idx_events_event_scope ON events(event_type, scope_status);
CREATE INDEX idx_events_observed_at ON events(observed_at);
CREATE INDEX idx_provider_observations_hostname ON provider_observations(hostname);
CREATE INDEX idx_provider_observations_provider ON provider_observations(provider);
CREATE INDEX idx_provider_health_provider ON provider_health(provider);
CREATE INDEX idx_dns_validations_hostname ON dns_validations(hostname);
CREATE INDEX idx_dns_validations_state ON dns_validations(dns_state);
CREATE INDEX idx_dns_validations_host_time ON dns_validations(hostname, observed_at);
CREATE INDEX idx_objects_type_value ON objects(object_type, value);
CREATE TRIGGER reject_boom before insert on objects when new.object_id='eventobj:boom:x' begin select raise(abort,'fixture rollback'); end;
COMMIT;
