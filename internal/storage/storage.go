package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"asmtool/internal/backends"
	"asmtool/internal/evidence"
	_ "modernc.org/sqlite"
)

const DDL = `PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS events(event_id TEXT PRIMARY KEY,event_type TEXT NOT NULL,module TEXT NOT NULL,source_tool TEXT,observed_at TEXT,raw_value TEXT,normalized_value TEXT,scope_status TEXT,confidence REAL,evidence TEXT,relations TEXT,metadata TEXT);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_source_tool ON events(source_tool);
CREATE INDEX IF NOT EXISTS idx_events_event_scope ON events(event_type,scope_status);
CREATE INDEX IF NOT EXISTS idx_events_observed_at ON events(observed_at);
CREATE TABLE IF NOT EXISTS objects(object_id TEXT PRIMARY KEY,object_type TEXT NOT NULL,value TEXT NOT NULL,first_seen TEXT,last_seen TEXT,sources TEXT NOT NULL DEFAULT '[]',scope_status TEXT,confidence REAL,data TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS relations(relation_id TEXT PRIMARY KEY,source_id TEXT,target_id TEXT,relation_type TEXT,evidence TEXT);
CREATE TABLE IF NOT EXISTS limitations(limitation_id TEXT PRIMARY KEY,observed_at TEXT,reason TEXT,data TEXT);
CREATE TABLE IF NOT EXISTS build_log(key TEXT PRIMARY KEY,value TEXT);
CREATE TABLE IF NOT EXISTS provider_observations(event_id TEXT PRIMARY KEY,hostname TEXT NOT NULL,provider TEXT NOT NULL,collector TEXT,evidence_family TEXT,first_seen_by_provider TEXT,observed_at TEXT,scope_status TEXT,metadata TEXT);
CREATE INDEX IF NOT EXISTS idx_provider_observations_hostname ON provider_observations(hostname);
CREATE INDEX IF NOT EXISTS idx_provider_observations_provider ON provider_observations(provider);
CREATE TABLE IF NOT EXISTS provider_health(event_id TEXT PRIMARY KEY,provider TEXT NOT NULL,collector TEXT,role TEXT,status TEXT,observed_at TEXT,data TEXT);
CREATE INDEX IF NOT EXISTS idx_provider_health_provider ON provider_health(provider);
CREATE TABLE IF NOT EXISTS dns_validations(event_id TEXT PRIMARY KEY,hostname TEXT NOT NULL,dns_state TEXT,active_eligibility TEXT,parent_zone TEXT,observed_at TEXT,data TEXT);
CREATE INDEX IF NOT EXISTS idx_dns_validations_hostname ON dns_validations(hostname);
CREATE INDEX IF NOT EXISTS idx_dns_validations_state ON dns_validations(dns_state);
CREATE INDEX IF NOT EXISTS idx_dns_validations_host_time ON dns_validations(hostname,observed_at);
CREATE INDEX IF NOT EXISTS idx_objects_type_value ON objects(object_type,value);`

func Open(path string) (*sql.DB, error) {
	if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		return nil, e
	}
	dsn, e := sqliteFileDSN(path, "")
	if e != nil {
		return nil, e
	}
	db, e := sql.Open("sqlite", dsn)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	return db, nil
}
func Connect(ctx context.Context, path string) (*sql.DB, error) {
	if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	created := e == nil
	if e != nil && !errors.Is(e, os.ErrExist) {
		return nil, e
	}
	if f != nil {
		if e = f.Close(); e != nil {
			_ = os.Remove(path)
			return nil, e
		}
	}
	db, e := Open(path)
	if e != nil {
		return nil, e
	}
	if created {
		if _, e = db.ExecContext(ctx, DDL); e != nil {
			_ = db.Close()
			for _, p := range []string{path, path + "-wal", path + "-shm"} {
				_ = os.Remove(p)
			}
			return nil, e
		}
	}
	return db, nil
}

func json(v any) (string, error) {
	b, e := backends.EncodeJSON(v, false, true, false)
	return string(b), e
}
func s(v any) string {
	if v == nil {
		return ""
	}
	return pyString(v)
}
func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }

func ObjectID(ev map[string]any) (string, string, bool) {
	et := s(ev["event_type"])
	nv := ev["normalized_value"]
	value := pyString(nv)
	if m, ok := nv.(map[string]any); ok {
		value = ""
		for _, k := range []string{"value", "url", "ip"} {
			if truthy(m[k]) {
				value = pyString(m[k])
				break
			}
		}
		if value == "" {
			value, _ = json(m)
		}
	}
	switch et {
	case "domain_found", "subdomain_found":
		return "domain:" + value, "domain", true
	case "tls_name_found":
		return "tlsname:" + value, "tls_name", true
	case "ip_found":
		return "ip:" + value, "ip", true
	case "cidr_found":
		return "cidr:" + value, "cidr", true
	case "asn_found":
		return "asn:" + value, "asn", true
	case "tls_certificate_found":
		return "tls:" + value, "tls_certificate", true
	case "web_target_status":
		return "webtarget:" + value, "web_target", true
	case "dns_record_found":
		if m, ok := nv.(map[string]any); ok {
			name, typ, val := m["name"], m["type"], m["value"]
			if !truthy(name) {
				name = ""
			}
			if !truthy(typ) {
				typ = ""
			}
			if !truthy(val) {
				val = ""
			}
			return "dns:" + pyString(name) + ":" + strings.ToUpper(pyString(typ)) + ":" + pyString(val), "dns_record", true
		}
	case "port_scan_result":
		m := obj(ev["metadata"])
		return "tcp:" + pyString(m["ip"]) + ":" + pyString(m["port"]), "port_scan_result", true
	case "port_found":
		m := obj(ev["metadata"])
		ip, exists := m["ip"]
		if !exists {
			ip = "unknown"
		}
		proto, exists := m["protocol"]
		if !exists {
			proto = "tcp"
		}
		port, exists := m["port"]
		if !exists {
			port = value
		}
		return "service:" + pyString(ip) + ":" + pyString(proto) + ":" + pyString(port), "service", true
	case "screenshot_saved":
		m := obj(ev["metadata"])
		h := m["sha256"]
		if !truthy(h) {
			h = value
		}
		url := m["url"]
		if !truthy(url) {
			url = value
		}
		domain := m["target_domain"]
		if !truthy(domain) {
			domain = ""
		}
		d := sha256.Sum256([]byte(pyString(domain) + "|" + pyString(url)))
		return fmt.Sprintf("screenshot:%s:%s", hex.EncodeToString(d[:])[:16], pyString(h)), "screenshot", true
	case "limitation", "source_health", "dns_validation":
		return "", "", false
	case "web_service_found", "url_found", "html_analyzed", "js_endpoint_found", "crawler_result", "aggressive_crawl_result":
		return "url:" + value, "url", true
	}
	return "eventobj:" + et + ":" + value, et, true
}

func pyString(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case string:
		return x
	case stdjson.Number:
		return pythonNumber(string(x))
	case []any:
		parts := make([]string, len(x))
		for i, v := range x {
			parts[i] = pyRepr(v)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		return pyRepr(x)
	default:
		return fmt.Sprint(v)
	}
}

func pyRepr(v any) string {
	switch x := v.(type) {
	case string:
		quote := byte('\'')
		if strings.ContainsRune(x, '\'') && !strings.ContainsRune(x, '"') {
			quote = '"'
		}
		var b strings.Builder
		b.WriteByte(quote)
		for _, r := range x {
			switch r {
			case '\\':
				b.WriteString("\\\\")
			case rune(quote):
				b.WriteByte('\\')
				b.WriteRune(r)
			case '\n':
				b.WriteString("\\n")
			case '\r':
				b.WriteString("\\r")
			case '\t':
				b.WriteString("\\t")
			default:
				if r < 0x20 || r == 0x7f {
					b.WriteString(fmt.Sprintf("\\x%02x", r))
				} else {
					b.WriteRune(r)
				}
			}
		}
		b.WriteByte(quote)
		return b.String()
	case []any:
		parts := make([]string, len(x))
		for i, item := range x {
			parts[i] = pyRepr(item)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, pyRepr(k)+": "+pyRepr(x[k]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	default:
		return pyString(v)
	}
}

func pythonNumber(raw string) string {
	if _, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return raw
	}
	if !strings.ContainsAny(raw, ".eE") {
		if n, ok := new(big.Int).SetString(raw, 10); ok {
			return n.String()
		}
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return raw
	}
	scientific := strconv.FormatFloat(f, 'e', -1, 64)
	i := strings.LastIndexByte(scientific, 'e')
	if i < 0 {
		return scientific
	}
	exponent, expErr := strconv.Atoi(scientific[i+1:])
	if expErr != nil {
		return raw
	}
	out := scientific
	if exponent >= -4 && exponent < 16 {
		out = strconv.FormatFloat(f, 'f', -1, 64)
		if !strings.ContainsRune(out, '.') {
			out += ".0"
		}
	}
	return out
}
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	case int:
		return x != 0
	case stdjson.Number:
		f, e := x.Float64()
		return e == nil && f != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

func IngestEvent(ctx context.Context, db *sql.DB, ev map[string]any) (bool, error) {
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		return false, e
	}
	ok, e := IngestEventTx(ctx, tx, ev)
	if e != nil {
		_ = tx.Rollback()
		return false, e
	}
	if e = tx.Commit(); e != nil {
		return false, e
	}
	return ok, nil
}

func IngestEventTx(ctx context.Context, tx *sql.Tx, ev map[string]any) (bool, error) {
	eid := s(ev["event_id"])
	if eid == "" {
		return false, errors.New("event_id is empty")
	}
	if _, e := tx.ExecContext(ctx, "SAVEPOINT asm_ingest_event"); e != nil {
		return false, e
	}
	rollback := func(cause error) (bool, error) {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, rbErr := tx.ExecContext(cleanupCtx, "ROLLBACK TO SAVEPOINT asm_ingest_event")
		_, relErr := tx.ExecContext(cleanupCtx, "RELEASE SAVEPOINT asm_ingest_event")
		if rbErr != nil || relErr != nil {
			// A caller-owned transaction must not be able to commit a partial event.
			return false, errors.Join(cause, rbErr, relErr, tx.Rollback())
		}
		return false, cause
	}
	var exists int
	e := tx.QueryRowContext(ctx, "SELECT 1 FROM events WHERE event_id=?", eid).Scan(&exists)
	if e == nil {
		if _, e = tx.ExecContext(ctx, "RELEASE SAVEPOINT asm_ingest_event"); e != nil {
			return rollback(e)
		}
		return false, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return rollback(e)
	}
	if e = backends.ValidateEvent(ev); e != nil {
		return rollback(e)
	}
	fields := []string{"event_type", "module", "source_tool", "observed_at", "raw_value", "normalized_value", "scope_status", "confidence", "evidence", "relations", "metadata"}
	vals := make([]any, 0, 12)
	vals = append(vals, eid)
	for _, k := range fields {
		if k == "raw_value" || k == "normalized_value" || k == "evidence" || k == "relations" || k == "metadata" {
			j, je := json(ev[k])
			if je != nil {
				return rollback(je)
			}
			vals = append(vals, j)
		} else {
			vals = append(vals, ev[k])
		}
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO events(event_id,event_type,module,source_tool,observed_at,raw_value,normalized_value,scope_status,confidence,evidence,relations,metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", vals...); e != nil {
		return rollback(e)
	}
	meta := obj(ev["metadata"])
	et := s(ev["event_type"])
	observed := ev["observed_at"]
	switch et {
	case "domain_found", "subdomain_found":
		if truthy(meta["provider"]) {
			j, je := json(meta)
			if je != nil {
				return rollback(je)
			}
			_, e = tx.ExecContext(ctx, "INSERT INTO provider_observations(event_id,hostname,provider,collector,evidence_family,first_seen_by_provider,observed_at,scope_status,metadata) VALUES(?,?,?,?,?,?,?,?,?)", eid, s(ev["normalized_value"]), s(meta["provider"]), s(meta["collector_tool"]), s(meta["evidence_family"]), meta["first_seen_by_provider"], observed, ev["scope_status"], j)
		}
	case "source_health":
		j, je := json(meta)
		if je != nil {
			return rollback(je)
		}
		provider := meta["provider"]
		if !truthy(provider) {
			provider = ev["source_tool"]
		}
		_, e = tx.ExecContext(ctx, "INSERT INTO provider_health(event_id,provider,collector,role,status,observed_at,data) VALUES(?,?,?,?,?,?,?)", eid, s(provider), s(meta["collector"]), s(meta["role"]), s(meta["status"]), observed, j)
	case "dns_validation":
		j, je := json(meta)
		if je != nil {
			return rollback(je)
		}
		_, e = tx.ExecContext(ctx, "INSERT INTO dns_validations(event_id,hostname,dns_state,active_eligibility,parent_zone,observed_at,data) VALUES(?,?,?,?,?,?,?)", eid, s(ev["normalized_value"]), s(meta["dns_state"]), s(meta["active_eligibility"]), s(meta["parent_zone"]), observed, j)
	}
	if e != nil {
		return rollback(e)
	}
	if relations, ok := ev["relations"].([]any); ok {
		for _, r := range relations {
			m, ok := r.(map[string]any)
			if !ok {
				continue
			}
			sourceValue, targetValue := m["source_id"], m["target_id"]
			if !truthy(sourceValue) {
				sourceValue = ""
			}
			if !truthy(targetValue) {
				targetValue = ""
			}
			src, dst := pyString(sourceValue), pyString(targetValue)
			if src == "" || dst == "" {
				continue
			}
			typ := s(m["relation_type"])
			if !truthy(m["relation_type"]) {
				typ = "related_to"
			}
			sum := sha256.Sum256([]byte(src + "|" + typ + "|" + dst))
			ev := m["evidence"]
			if _, exists := m["evidence"]; !exists {
				ev = map[string]any{}
			}
			evd, je := json(ev)
			if je != nil {
				return rollback(je)
			}
			_, e = tx.ExecContext(ctx, "INSERT INTO relations(relation_id,source_id,target_id,relation_type,evidence) VALUES(?,?,?,?,?) ON CONFLICT(relation_id) DO UPDATE SET evidence=excluded.evidence", "rel:"+hex.EncodeToString(sum[:])[:24], src, dst, typ, evd)
			if e != nil {
				return rollback(e)
			}
		}
	}
	if et == "limitation" {
		full, je := json(ev)
		if je != nil {
			return rollback(je)
		}
		_, e = tx.ExecContext(ctx, "INSERT OR REPLACE INTO limitations(limitation_id,observed_at,reason,data) VALUES(?,?,?,?)", eid, observed, pyString(ev["raw_value"]), full)
		if e != nil {
			return rollback(e)
		}
	} else if id, typ, yes := ObjectID(ev); yes {
		if e = upsertObject(ctx, tx, ev, id, typ); e != nil {
			return rollback(e)
		}
	}
	if _, e = tx.ExecContext(ctx, "RELEASE SAVEPOINT asm_ingest_event"); e != nil {
		return rollback(e)
	}
	return true, nil
}

func upsertObject(ctx context.Context, tx *sql.Tx, ev map[string]any, id, typ string) error {
	var sourcesJSON, dataJSON string
	e := tx.QueryRowContext(ctx, "SELECT sources,data FROM objects WHERE object_id=?", id).Scan(&sourcesJSON, &dataJSON)
	sources := []any{}
	data := map[string]any{"events": []any{}}
	if e == nil {
		v, x := backends.DecodeJSON([]byte(sourcesJSON))
		if x != nil {
			return x
		}
		var ok bool
		sources, ok = v.([]any)
		if !ok {
			return errors.New("stored object sources is not an array")
		}
		v, x = backends.DecodeJSON([]byte(dataJSON))
		if x != nil {
			return x
		}
		data, ok = v.(map[string]any)
		if !ok {
			return errors.New("stored object data is not an object")
		}
	} else if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	source := ev["source_tool"]
	if !truthy(source) {
		source = ev["module"]
	}
	found := false
	for _, x := range sources {
		if s(x) == s(source) {
			found = true
		}
	}
	if !found && s(source) != "" {
		sources = append(sources, source)
	}
	ids, exists := data["events"]
	if !exists {
		ids = []any{}
	}
	eventIDs, ok := ids.([]any)
	if !ok {
		return errors.New("stored object data events is not an array")
	}
	eventIDs = append(eventIDs, ev["event_id"])
	data["events"] = eventIDs
	latest, _ := data["latest"].(map[string]any)
	if latest == nil || s(ev["observed_at"]) >= s(latest["observed_at"]) {
		data["latest"] = ev
	}
	sj, e := json(sources)
	if e != nil {
		return e
	}
	dj, e := json(data)
	if e != nil {
		return e
	}
	latestEvent := data["latest"].(map[string]any)
	value := strings.SplitN(id, ":", 2)
	v := ""
	if len(value) == 2 {
		v = value[1]
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO objects(object_id,object_type,value,first_seen,last_seen,sources,scope_status,confidence,data) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(object_id) DO UPDATE SET first_seen=MIN(objects.first_seen,excluded.first_seen),last_seen=MAX(objects.last_seen,excluded.last_seen),sources=excluded.sources,scope_status=excluded.scope_status,confidence=MAX(objects.confidence,excluded.confidence),data=excluded.data`, id, typ, v, ev["observed_at"], ev["observed_at"], sj, latestEvent["scope_status"], ev["confidence"], dj)
	return e
}

// IterEvents returns the legacy twelve-column event view in stable time/id order.
func IterEvents(ctx context.Context, db *sql.DB, types []string) ([]map[string]any, error) {
	q := "SELECT event_id,event_type,module,source_tool,observed_at,raw_value,normalized_value,scope_status,confidence,evidence,relations,metadata FROM events"
	args := []any{}
	if len(types) > 0 {
		q += " WHERE event_type IN (" + strings.TrimRight(strings.Repeat("?,", len(types)), ",") + ")"
		for _, v := range types {
			args = append(args, v)
		}
	}
	q += " ORDER BY observed_at,event_id"
	rows, e := db.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	result := []map[string]any{}
	for rows.Next() {
		var id, et, module string
		var source, observed, scope sql.NullString
		var raw, norm, evidence, relations, metadata sql.NullString
		var confidence sql.NullFloat64
		if e = rows.Scan(&id, &et, &module, &source, &observed, &raw, &norm, &scope, &confidence, &evidence, &relations, &metadata); e != nil {
			return nil, e
		}
		var sourceValue, observedValue, scopeValue, confidenceValue any
		if source.Valid {
			sourceValue = source.String
		}
		if observed.Valid {
			observedValue = observed.String
		}
		if scope.Valid {
			scopeValue = scope.String
		}
		if confidence.Valid {
			confidenceValue = confidence.Float64
		}
		m := map[string]any{"event_id": id, "event_type": et, "module": module, "source_tool": sourceValue, "observed_at": observedValue, "scope_status": scopeValue, "confidence": confidenceValue}
		jsonDefaults := map[string]any{"raw_value": map[string]any{}, "normalized_value": map[string]any{}, "evidence": map[string]any{}, "relations": []any{}, "metadata": map[string]any{}}
		for k, v := range map[string]sql.NullString{"raw_value": raw, "normalized_value": norm, "evidence": evidence, "relations": relations, "metadata": metadata} {
			m[k] = jsonDefaults[k]
			if v.Valid {
				x, xerr := backends.DecodeJSON([]byte(v.String))
				if xerr != nil {
					return nil, xerr
				}
				m[k] = x
			}
		}
		result = append(result, m)
	}
	return result, rows.Err()
}

// IngestJSONL reports malformed records by path and line, preserving good rows.
func IngestJSONL(ctx context.Context, db *sql.DB, paths []string) (map[string]any, error) {
	stats := map[string]any{"input_events": 0, "rejected": 0, "reasons": []any{}}
	reasons := []any{}
	for _, p := range paths {
		e := evidence.IterJSONL(p, func(r evidence.JSONLRecord) error {
			if r.Err != nil {
				stats["rejected"] = stats["rejected"].(int) + 1
				reasons = append(reasons, map[string]any{"path": r.Path, "line": r.Line, "error": r.Err.Error()})
				return nil
			}
			stats["input_events"] = stats["input_events"].(int) + 1
			if truthy(obj(r.Event["metadata"])["dry_run"]) {
				stats["rejected"] = stats["rejected"].(int) + 1
				reasons = append(reasons, map[string]any{"path": r.Path, "line": r.Line, "event_id": r.Event["event_id"], "reason": "dry_run event ignored"})
				return nil
			}
			_, x := IngestEvent(ctx, db, r.Event)
			if x != nil {
				stats["rejected"] = stats["rejected"].(int) + 1
				reasons = append(reasons, map[string]any{"path": r.Path, "line": r.Line, "event_id": r.Event["event_id"], "error": x.Error()})
			}
			return nil
		})
		if e != nil {
			stats["rejected"] = stats["rejected"].(int) + 1
			reasons = append(reasons, map[string]any{"path": p, "error": e.Error()})
		}
	}
	stats["reasons"] = reasons
	b, e := json(stats)
	if e != nil {
		return nil, e
	}
	_, e = db.ExecContext(ctx, "INSERT OR REPLACE INTO build_log(key,value) VALUES('ingest_stats',?)", b)
	return stats, e
}
