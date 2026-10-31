package storage

import (
	"asmtool/internal/backends"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	stdjson "encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func sampleEvent(id string) map[string]any {
	return map[string]any{"event_id": id, "event_type": "domain_found", "module": "passive", "source_tool": "crt.sh", "observed_at": "2026-01-01T00:00:00Z", "observed_at_local": "2026-01-01T03:00:00+03:00", "raw_value": "пример.example", "normalized_value": "xn--e1afmkfd.example", "scope_status": "in_scope", "confidence": 0.9, "evidence": map[string]any{"large": 9007199254740993}, "relations": []any{map[string]any{"source_id": "domain:root.example", "target_id": "ip:192.0.2.1", "relation_type": "resolves_to"}}, "metadata": map[string]any{"provider": "crt.sh", "collector_tool": "subfaster", "evidence_family": "certificate_transparency"}}
}
func TestLegacySchemaIngestReopenAndRollback(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db.sqlite3")
	db, e := Connect(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	var tables, indices int
	if e = db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`).Scan(&tables); e != nil {
		t.Fatal(e)
	}
	if e = db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'`).Scan(&indices); e != nil {
		t.Fatal(e)
	}
	if tables != 8 || indices != 11 {
		t.Fatalf("schema tables=%d indices=%d", tables, indices)
	}
	ev := sampleEvent("stable-id")
	if ok, e := IngestEvent(ctx, db, ev); e != nil || !ok {
		t.Fatalf("first ingest %v %v", ok, e)
	}
	changed := sampleEvent("stable-id")
	changed["normalized_value"] = "changed.example"
	if ok, e := IngestEvent(ctx, db, changed); e != nil || ok {
		t.Fatalf("duplicate ingest %v %v", ok, e)
	}
	var got string
	if e = db.QueryRow("SELECT normalized_value FROM events WHERE event_id='stable-id'").Scan(&got); e != nil || got != `"xn--e1afmkfd.example"` {
		t.Fatalf("first-writer event=%s err=%v", got, e)
	}
	var objects, rels, providers int
	_ = db.QueryRow("SELECT count(*) FROM objects").Scan(&objects)
	_ = db.QueryRow("SELECT count(*) FROM relations").Scan(&rels)
	_ = db.QueryRow("SELECT count(*) FROM provider_observations").Scan(&providers)
	if objects != 1 || rels != 1 || providers != 1 {
		t.Fatalf("projections objects=%d relations=%d provider=%d", objects, rels, providers)
	}
	if _, e = db.Exec(`CREATE TRIGGER reject_object BEFORE INSERT ON objects WHEN NEW.object_id='domain:rollback.example' BEGIN SELECT RAISE(ABORT,'fixture rejection'); END`); e != nil {
		t.Fatal(e)
	}
	bad := sampleEvent("rollback-id")
	bad["normalized_value"] = "rollback.example"
	callerTx, e := db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = IngestEventTx(ctx, callerTx, bad); e == nil {
		t.Fatal("expected projection failure")
	}
	if e = callerTx.Commit(); e != nil {
		t.Fatal(e)
	}
	var n int
	_ = db.QueryRow("SELECT count(*) FROM events WHERE event_id='rollback-id'").Scan(&n)
	if n != 0 {
		t.Fatal("event escaped savepoint rollback")
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	db, e = Connect(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	rows, e := IterEvents(ctx, db, []string{"domain_found"})
	if e != nil || len(rows) != 1 {
		t.Fatalf("reopen read: rows=%d err=%v", len(rows), e)
	}
}

func TestIterEventsReturnsAllTwelveKeysAndPreservesNullSemantics(t *testing.T) {
	db, err := Connect(context.Background(), filepath.Join(t.TempDir(), "events.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`INSERT INTO events(event_id,event_type,module,source_tool,observed_at,raw_value,normalized_value,scope_status,confidence,evidence,relations,metadata) VALUES('nulls','fixture','test',NULL,NULL,NULL,'null',NULL,NULL,NULL,'null','{}')`)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := IterEvents(context.Background(), db, nil)
	if err != nil || len(rows) != 1 {
		t.Fatalf("IterEvents rows=%d err=%v", len(rows), err)
	}
	r := rows[0]
	wantKeys := []string{"event_id", "event_type", "module", "source_tool", "observed_at", "raw_value", "normalized_value", "scope_status", "confidence", "evidence", "relations", "metadata"}
	if len(r) != len(wantKeys) {
		t.Fatalf("IterEvents returned %d keys, want 12: %#v", len(r), r)
	}
	for _, key := range wantKeys {
		if _, ok := r[key]; !ok {
			t.Errorf("missing key %q", key)
		}
	}
	for _, key := range []string{"source_tool", "observed_at", "scope_status", "confidence", "normalized_value"} {
		if r[key] != nil {
			t.Errorf("SQL NULL / JSON null %s = %#v; want nil", key, r[key])
		}
	}
	for _, key := range []string{"raw_value", "evidence"} {
		if v, ok := r[key].(map[string]any); !ok || len(v) != 0 {
			t.Errorf("SQL NULL %s=%#v, want empty object", key, r[key])
		}
	}
	if r["relations"] != nil {
		t.Errorf("JSON text null relations=%#v, want nil", r["relations"])
	}
	if v, ok := r["metadata"].(map[string]any); !ok || len(v) != 0 {
		t.Errorf("metadata default=%#v, want empty object", r["metadata"])
	}
}

func TestSQLiteReadDoesNotCreateSidecarOnMissingInput(t *testing.T) {
	p := filepath.Join(t.TempDir(), "missing.sqlite3")
	if db, e := OpenImmutable(p); e == nil {
		_ = db.Close()
		t.Fatal("missing DB unexpectedly opened")
	}
	if _, e := os.Lstat(p); !os.IsNotExist(e) {
		t.Fatalf("readonly open created DB: %v", e)
	}
}

func TestSQLiteURIAndSnapshotReaderLifecycle(t *testing.T) {
	if got := sqliteFileURI(`C:\ASM Tool\data.sqlite3`, true); got != "file:///C:/ASM%20Tool/data.sqlite3" {
		t.Fatalf("Windows URI=%q", got)
	}
	if got := sqliteFileURI("/tmp/a b.sqlite3", false); got != "file:///tmp/a%20b.sqlite3" {
		t.Fatalf("Unix URI=%q", got)
	}
	ctx := context.Background()
	dir := t.TempDir()
	src := filepath.Join(dir, "legacy.sqlite3")
	db, e := sql.Open("sqlite", src)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("CREATE TABLE t(v TEXT); INSERT INTO t VALUES('ok')"); e != nil {
		t.Fatal(e)
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	snap, e := OpenLegacySnapshot(ctx, src)
	if e != nil {
		t.Fatal(e)
	}
	path := snap.path
	var v string
	if e = snap.DB.QueryRow("SELECT v FROM t").Scan(&v); e != nil || v != "ok" {
		t.Fatalf("snapshot reader: %q %v", v, e)
	}
	if e = snap.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatalf("snapshot scratch survived Close: %v", e)
	}
}

func TestSQLiteQuestionHashPercentUnicodePathRoundTripAndSnapshot(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("path behavior regression is Linux-specific")
	}
	ctx := context.Background()
	dir := t.TempDir()
	source := filepath.Join(dir, "db?query#fragment%Ж.sqlite3")
	db, err := Connect(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE marker(value TEXT); INSERT INTO marker VALUES('round-trip')`); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(dir, "db")); !os.IsNotExist(err) {
		t.Fatalf("SQLite created/truncated a DSN-prefix file: %v", err)
	}
	destination := filepath.Join(t.TempDir(), "copy?query#fragment%Ж.sqlite3")
	if err = CopyLegacySnapshot(ctx, source, destination); err != nil {
		t.Fatal(err)
	}
	copyDB, err := OpenImmutable(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer copyDB.Close()
	var got string
	if err = copyDB.QueryRow("SELECT value FROM marker").Scan(&got); err != nil || got != "round-trip" {
		t.Fatalf("snapshot row=%q err=%v", got, err)
	}
	if _, err = os.Stat(filepath.Join(filepath.Dir(destination), "copy")); !os.IsNotExist(err) {
		t.Fatalf("SQLite created/truncated destination DSN-prefix file: %v", err)
	}
}

func TestCopyLegacySnapshotRejectsSymlinkAndCorruptDB(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.sqlite3")
	db, e := Connect(context.Background(), good)
	if e != nil {
		t.Fatal(e)
	}
	_ = db.Close()
	link := filepath.Join(dir, "alias.sqlite3")
	if e = os.Symlink(good, link); e != nil {
		t.Skipf("symlink unavailable: %v", e)
	}
	if e = CopyLegacySnapshot(context.Background(), link, filepath.Join(dir, "copy.sqlite3")); e == nil {
		t.Fatal("symlinked source accepted")
	}
	bad := filepath.Join(dir, "bad.sqlite3")
	if e = os.WriteFile(bad, []byte("not a SQLite database"), 0600); e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(t.TempDir(), "bad-copy.sqlite3")
	if e = CopyLegacySnapshot(context.Background(), bad, out); e == nil {
		t.Fatal("corrupt source accepted")
	}
	if _, e = os.Lstat(out); !os.IsNotExist(e) {
		t.Fatalf("failed copy left output: %v", e)
	}
}

func TestStorageSourceFixtureIdentityAndJSONL(t *testing.T) {
	b, err := os.ReadFile("../../testdata/phase2/legacy_contract.json")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := backends.DecodeJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	fixture := decoded.(map[string]any)
	for _, raw := range fixture["python_identity_string_cases"].([]any) {
		m := raw.(map[string]any)
		id, _, ok := ObjectID(map[string]any{"event_type": "other", "normalized_value": m["value"]})
		if !ok || id != m["object_id"] {
			t.Fatalf("source identity got %q want %q", id, m["object_id"])
		}
	}
	for _, raw := range fixture["screenshot_identity_cases"].([]any) {
		m := raw.(map[string]any)
		id, _, ok := ObjectID(m["event"].(map[string]any))
		if !ok || id != m["object_id"] {
			t.Fatalf("source screenshot identity got %q want %q", id, m["object_id"])
		}
	}
	sqlite := fixture["sqlite"].(map[string]any)
	for i, raw := range sqlite["screenshot_objects"].([]any) {
		want := raw.(map[string]any)
		value := "https://app.example.test/"
		metadata := map[string]any{"sha256": strings.Repeat("a", 64), "url": value, "target_domain": "example.test"}
		if i == 1 {
			value = "https://fallback.example.test/"
			metadata = map[string]any{"sha256": "", "url": "", "target_domain": "example.test"}
		}
		id, typ, ok := ObjectID(map[string]any{"event_type": "screenshot_saved", "normalized_value": value, "metadata": metadata})
		if !ok || id != want["object_id"] || typ != want["object_type"] {
			t.Fatalf("screenshot fixture got %s/%s want %#v", id, typ, want)
		}
	}
	jsonl := fixture["jsonl"].(map[string]any)
	path := filepath.Join(t.TempDir(), "events.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range jsonl["lines"].([]any) {
		if _, err = f.WriteString(line.(string) + "\n"); err != nil {
			t.Fatal(err)
		}
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := Connect(context.Background(), filepath.Join(t.TempDir(), "db.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stats, err := IngestJSONL(context.Background(), db, []string{path})
	if err != nil {
		t.Fatal(err)
	}
	wantStats := jsonl["ingest_stats_without_elapsed"].(map[string]any)
	wantInput, _ := wantStats["input_events"].(stdjson.Number).Int64()
	wantRejected, _ := wantStats["rejected"].(stdjson.Number).Int64()
	if stats["input_events"] != int(wantInput) || stats["rejected"] != int(wantRejected) {
		t.Fatalf("fixture ingest stats=%#v want input=%d rejected=%d", stats, wantInput, wantRejected)
	}
	var events, objects int
	if err = db.QueryRow("SELECT count(*) FROM events").Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow("SELECT count(*) FROM objects").Scan(&objects); err != nil {
		t.Fatal(err)
	}
	wantCounts := jsonl["ingest_table_counts"].(map[string]any)
	expectedEvents, _ := wantCounts["events"].(stdjson.Number).Int64()
	expectedObjects, _ := wantCounts["objects"].(stdjson.Number).Int64()
	if events != int(expectedEvents) || objects != int(expectedObjects) {
		t.Fatalf("fixture tables events=%d objects=%d want %v", events, objects, wantCounts)
	}
}

func TestSyntheticLegacyRunSQLReadOnlyProjection(t *testing.T) {
	// This generated fixture is synthetic source-backed evidence, not a historical run.
	sqlBytes, err := os.ReadFile("../../testdata/phase2/synthetic_legacy_run.sql")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "synthetic.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(string(sqlBytes)); err != nil {
		t.Fatal(err)
	}
	var tables, indexes int
	if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'").Scan(&indexes); err != nil {
		t.Fatal(err)
	}
	if tables != 8 || indexes != 11 {
		t.Fatalf("synthetic source schema tables=%d indexes=%d", tables, indexes)
	}
	rows, err := IterEvents(context.Background(), db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("synthetic source database did not provide event rows")
	}
}

func TestSourceFixtureReplayMatchesSQLiteProjectionsAndSchema(t *testing.T) {
	b, err := os.ReadFile("../../testdata/phase2/legacy_contract.json")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := backends.DecodeJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	fixture := decoded.(map[string]any)
	sqlite := fixture["sqlite"].(map[string]any)
	path := filepath.Join(t.TempDir(), "replay.sqlite3")
	db, err := Connect(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range sqlite["input_events"].([]any) {
		if _, err = IngestEvent(context.Background(), db, raw.(map[string]any)); err != nil {
			t.Fatal(err)
		}
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Connect(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for table, wantRaw := range sqlite["schema"].(map[string]any)["columns"].(map[string]any) {
		want := wantRaw.([]any)
		rows, qerr := db.Query("PRAGMA table_info(" + table + ")")
		if qerr != nil {
			t.Fatal(qerr)
		}
		var got [][]any
		for rows.Next() {
			var cid, notnull, pk int
			var name, typ string
			var def any
			if qerr = rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); qerr != nil {
				t.Fatal(qerr)
			}
			got = append(got, []any{int64(cid), name, typ, int64(notnull), normalizeSQLiteValue(def), int64(pk)})
		}
		if qerr = rows.Err(); qerr != nil {
			t.Fatal(qerr)
		}
		_ = rows.Close()
		assertJSONEqual(t, table+" columns", got, want)
	}
	for index, wantRaw := range sqlite["schema"].(map[string]any)["index_columns"].(map[string]any) {
		rows, qerr := db.Query("PRAGMA index_info(" + index + ")")
		if qerr != nil {
			t.Fatal(qerr)
		}
		var got [][]any
		for rows.Next() {
			var seq, cid int
			var name any
			if qerr = rows.Scan(&seq, &cid, &name); qerr != nil {
				t.Fatal(qerr)
			}
			got = append(got, []any{int64(seq), int64(cid), normalizeSQLiteValue(name)})
		}
		if qerr = rows.Err(); qerr != nil {
			t.Fatal(qerr)
		}
		_ = rows.Close()
		assertJSONEqual(t, index+" columns", got, wantRaw)
	}

	models := sqlite["specialized_read_models"].(map[string]any)
	wantTables := map[string][]any{
		"objects":   append(append([]any{}, sqlite["object_merge"].([]any)...), sqlite["screenshot_objects"].([]any)...),
		"relations": sqlite["relation_rows"].([]any),
	}
	for table, rows := range models {
		wantTables[table] = rows.([]any)
	}
	keys := map[string]string{"objects": "object_id", "relations": "relation_id", "provider_observations": "event_id", "provider_health": "event_id", "dns_validations": "event_id", "limitations": "limitation_id"}
	for table, expected := range wantTables {
		columns := make([]string, 0)
		if len(expected) > 0 {
			seen := map[string]bool{}
			for _, exp := range expected {
				for key := range exp.(map[string]any) {
					if !seen[key] {
						columns = append(columns, key)
						seen[key] = true
					}
				}
			}
			sort.Strings(columns)
		}
		if len(columns) == 0 {
			continue
		}
		args := make([]any, 0, len(expected))
		for _, exp := range expected {
			args = append(args, exp.(map[string]any)[keys[table]])
		}
		marks := strings.TrimRight(strings.Repeat("?,", len(args)), ",")
		rows, qerr := db.Query("SELECT "+strings.Join(columns, ",")+" FROM "+table+" WHERE "+keys[table]+" IN ("+marks+") ORDER BY "+keys[table], args...)
		if qerr != nil {
			t.Fatal(qerr)
		}
		var got []map[string]any
		for rows.Next() {
			values := make([]any, len(columns))
			ptrs := make([]any, len(columns))
			for i := range values {
				ptrs[i] = &values[i]
			}
			if qerr = rows.Scan(ptrs...); qerr != nil {
				t.Fatal(qerr)
			}
			row := map[string]any{}
			for i, col := range columns {
				row[col] = normalizeSQLiteValue(values[i])
			}
			got = append(got, row)
		}
		if qerr = rows.Err(); qerr != nil {
			t.Fatal(qerr)
		}
		_ = rows.Close()
		filtered := make([]map[string]any, len(got))
		for i, exp := range expected {
			filtered[i] = map[string]any{}
			for key := range exp.(map[string]any) {
				filtered[i][key] = got[i][key]
			}
		}
		assertJSONEqual(t, table+" projection", filtered, expected)
	}
}

func normalizeSQLiteValue(v any) any {
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return v
}

func assertJSONEqual(t *testing.T, what string, got, want any) {
	t.Helper()
	gb, err := backends.EncodeJSON(got, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	wb, err := backends.EncodeJSON(want, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(gb) != string(wb) {
		t.Fatalf("%s mismatch\n got: %s\nwant: %s", what, gb, wb)
	}
}

type diskState struct {
	present bool
	size    int64
	hash    string
	info    os.FileInfo
}

func independentlyHashDB(t *testing.T, base string) map[string]diskState {
	t.Helper()
	out := map[string]diskState{}
	for _, p := range []string{base, base + "-wal", base + "-shm", base + "-journal"} {
		st, e := os.Lstat(p)
		if os.IsNotExist(e) {
			out[p] = diskState{}
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		b, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		h := sha256.Sum256(b)
		out[p] = diskState{true, st.Size(), hex.EncodeToString(h[:]), st}
	}
	return out
}
func assertDiskStateEqual(t *testing.T, a, b map[string]diskState) {
	t.Helper()
	for path, x := range a {
		y, ok := b[path]
		if !ok || x.present != y.present || x.size != y.size || x.hash != y.hash || (x.present && !os.SameFile(x.info, y.info)) {
			t.Fatalf("source file changed: %s before=%+v after=%+v", path, x, y)
		}
	}
}

func TestLegacyWALSnapshotPreservesSourceAndCommittedRows(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	src := filepath.Join(dir, "legacy.sqlite3")
	dst := filepath.Join(t.TempDir(), "copy.sqlite3")
	db, e := sql.Open("sqlite", src)
	if e != nil {
		t.Fatal(e)
	}
	for _, q := range []string{"PRAGMA journal_mode=WAL", "PRAGMA wal_autocheckpoint=0", "CREATE TABLE legacy(value TEXT)", "INSERT INTO legacy VALUES('committed-in-wal')"} {
		if _, e = db.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
	wal := src + "-wal"
	st, e := os.Stat(wal)
	if e != nil || st.Size() <= 32 {
		t.Fatalf("fixture lacks uncheckpointed WAL: %v", e)
	}
	before := independentlyHashDB(t, src)
	if _, e = OpenImmutable(src); e == nil {
		t.Fatal("immutable reader silently accepted uncheckpointed WAL data")
	}
	if e = CopyLegacySnapshot(ctx, src, dst); e != nil {
		t.Fatal(e)
	}
	after := independentlyHashDB(t, src)
	assertDiskStateEqual(t, before, after)
	copyDB, e := OpenImmutable(dst)
	if e != nil {
		t.Fatal(e)
	}
	defer copyDB.Close()
	var value string
	if e = copyDB.QueryRow("SELECT value FROM legacy").Scan(&value); e != nil || value != "committed-in-wal" {
		t.Fatalf("snapshot dropped committed WAL row: %q %v", value, e)
	}
	nested := filepath.Join(dir, "nested")
	if e = os.Mkdir(nested, 0700); e != nil {
		t.Fatal(e)
	}
	if e = CopyLegacySnapshot(ctx, src, filepath.Join(nested, "copy.sqlite3")); e == nil {
		t.Fatal("destination inside legacy database directory was accepted")
	}
	if e = CopyLegacySnapshot(ctx, src, dst); e == nil {
		t.Fatal("existing destination was accepted")
	}
	for _, tc := range []struct {
		name   string
		damage func([]byte) []byte
	}{
		{"header", func(b []byte) []byte { b[0] ^= 0xff; return b }},
		{"salt", func(b []byte) []byte { b[16] ^= 0xff; return b }},
		{"checksum", func(b []byte) []byte {
			page := binary.BigEndian.Uint32(b[8:12])
			if page == 1 {
				page = 65536
			}
			off := len(b) - int(24+page) + 16
			b[off] ^= 0xff
			return b
		}},
		{"truncated", func(b []byte) []byte { return b[:len(b)-1] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			badDir := t.TempDir()
			badSource := filepath.Join(badDir, "damaged.sqlite3")
			if e := copyFile(src, badSource); e != nil {
				t.Fatal(e)
			}
			walData, e := os.ReadFile(src + "-wal")
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(badSource+"-wal", tc.damage(walData), 0600); e != nil {
				t.Fatal(e)
			}
			out := filepath.Join(t.TempDir(), "copy.sqlite3")
			if e = CopyLegacySnapshot(ctx, badSource, out); e == nil {
				t.Fatal("damaged WAL accepted")
			}
			if _, e = os.Lstat(out); !os.IsNotExist(e) {
				t.Fatalf("failed damaged WAL snapshot left destination: %v", e)
			}
		})
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
}
