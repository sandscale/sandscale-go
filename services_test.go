// Copyright 2026 Neural Inverse
// SPDX-License-Identifier: Apache-2.0

package sandscale

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func ctx() context.Context { return context.Background() }

func TestSandboxCreate(t *testing.T) {
	m := newMock(t)
	m.json("POST /api/v1/sandbox/instances", 201, `{"id":"sb1","status":"running","template_id":"builtin:python","cpu_count":1,"mem_mb":512,"ttl_seconds":600,
		"created_at":"2026-11-18T00:00:00Z","suspend":{"can_pause":true,"can_resume":false}}`)
	var box *Sandbox
	var err error
	box, err = m.client().Sandboxes.Create(ctx(), CreateSandboxParams{
		Template: "builtin:python", TTLSeconds: 600, Network: "allowlist", Env: map[string]string{"A": "1"},
		VaultEnv: []VaultEnvRef{{Name: "DB_PASSWORD", Path: "secret/data/db", Field: "password"}},
		Metadata: map[string]string{"project_id": "p1"}, Labels: map[string]string{"k": "v"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := bodyOf(t, m.last())
	want := map[string]any{
		"template_id": "builtin:python", "ttl_seconds": float64(600), "network": "allowlist", "env": map[string]any{"A": "1"},
		"vault_env": []any{map[string]any{"name": "DB_PASSWORD", "path": "secret/data/db", "field": "password"}},
		"metadata":  map[string]any{"project_id": "p1"}, "labels": map[string]any{"k": "v"},
	}
	if !reflect.DeepEqual(body, want) {
		t.Fatalf("body %v\nwant %v", body, want)
	}
	if box.ID != "sb1" || box.Status != "running" || box.CPUCount != 1 || box.MemMB != 512 || box.TTLSeconds != 600 ||
		box.CreatedAt.Year() != 2026 || box.Suspend == nil || !box.Suspend.CanPause || box.Suspend.CanResume || len(box.Raw) == 0 {
		t.Fatalf("%+v", box)
	}
	// An empty request sends an empty object, not nulls.
	if _, err := m.client().Sandboxes.Create(ctx(), CreateSandboxParams{}); err != nil {
		t.Fatal(err)
	}
	if string(m.last().Body) != "{}" {
		t.Fatalf("empty body: %s", m.last().Body)
	}
}

func regionServer(t *testing.T, regions string, h map[string]http.HandlerFunc) *Client {
	m := newMock(t)
	m.json("GET /api/v1/regions", 200, regions)
	for k, v := range h {
		m.on(k, v)
	}
	return m.client()
}

func TestRegionsFromServerList(t *testing.T) {
	var us, eu *mock
	us, eu = newMock(t), newMock(t)
	us.json("GET /api/v1/sandbox/instances", 200, `{"data":[{"id":"u1","status":"running"}],"has_more":true,"next_cursor":"c1"}`)
	eu.json("GET /api/v1/sandbox/instances", 200, `{"data":[{"id":"e1","status":"running"}],"has_more":false,"next_cursor":null}`)
	home := newMock(t)
	home.json("GET /api/v1/regions", 200, fmt.Sprintf(`{"regions":[
		{"id":"us1","status":"live","api_url":%q},{"id":"eu1","status":"live","api_url":%q},{"id":"ap1","status":"coming_soon"}]}`, us.srv.URL, eu.srv.URL))
	c := home.client()

	list, err := c.Sandboxes.List(ctx(), ListSandboxesParams{Status: "running", Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Data) != 2 || len(list.Pages) != 2 {
		t.Fatalf("every live region is read: %+v", list)
	}
	byRegion := map[string]Sandbox{}
	for _, s := range list.Data {
		byRegion[s.Region] = s
	}
	if byRegion["us1"].ID != "u1" || byRegion["eu1"].ID != "e1" {
		t.Fatalf("each sandbox knows its region: %+v", byRegion)
	}
	if got := us.last().Query; got != "limit=5&status=running" {
		t.Fatalf("query %q", got)
	}
	if home.count() != 1 {
		t.Fatalf("the home server only served the region list, saw %d requests", home.count())
	}
	for _, p := range list.Pages {
		if p.Region == "us1" && (!p.HasMore || p.NextCursor != "c1") {
			t.Fatalf("page %+v", p)
		}
	}
	// A name resolves to the one live region whose id is the name plus digits, and the call goes there.
	if _, err := c.Sandboxes.Get(ctx(), "u1", WithRegion("us")); err == nil {
		t.Fatal("the us mock has no GET route for u1, want a 404")
	}
	if us.last().Path != "/api/v1/sandbox/instances/u1" {
		t.Fatalf("the call went to the us region: %+v", us.last())
	}
	// Unknown and unavailable regions are region errors, before any call.
	for _, r := range []string{"mars", "ap"} {
		if _, err := c.Sandboxes.Get(ctx(), "u1", WithRegion(r)); !errors.Is(err, ErrRegion) {
			t.Fatalf("region %s: %v", r, err)
		}
	}
}

func TestListPartialFailureAndTotalFailure(t *testing.T) {
	good, bad := newMock(t), newMock(t)
	good.json("GET /api/v1/sandbox/instances", 200, `{"data":[{"id":"g1","status":"running"}]}`)
	bad.json("GET /api/v1/sandbox/instances", 403, `{"error":{"code":"wrong_region","message":"home is us1","region":"us1"}}`)
	home := newMock(t)
	home.json("GET /api/v1/regions", 200, fmt.Sprintf(`{"regions":[{"id":"us1","status":"live","api_url":%q},{"id":"eu1","status":"live","api_url":%q}]}`, good.srv.URL, bad.srv.URL))
	list, err := home.client().Sandboxes.List(ctx(), ListSandboxesParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Data) != 1 || list.Data[0].ID != "g1" {
		t.Fatalf("the readable region's sandboxes are returned: %+v", list.Data)
	}
	var failed int
	for _, p := range list.Pages {
		if p.Err != nil {
			failed++
			if p.Region != "eu1" || !errors.Is(p.Err, ErrRegion) {
				t.Fatalf("page %+v", p)
			}
		}
	}
	if failed != 1 {
		t.Fatalf("pages %+v", list.Pages)
	}
	good.json("GET /api/v1/sandbox/instances", 401, `{"error":{"code":"unauthorized","message":"bad key"}}`)
	bad.json("GET /api/v1/sandbox/instances", 401, `{"error":{"code":"unauthorized","message":"bad key"}}`)
	if _, err := home.client().Sandboxes.List(ctx(), ListSandboxesParams{}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("when every region fails the error is returned: %v", err)
	}
}

func TestListSingleRegionInstallation(t *testing.T) {
	m := newMock(t)
	m.json("GET /api/v1/regions", 200, `{"regions":[]}`)
	m.json("GET /api/v1/sandbox/instances", 200, `{"data":[{"id":"a","status":"running"}]}`)
	list, err := m.client().Sandboxes.List(ctx(), ListSandboxesParams{})
	if err != nil || len(list.Data) != 1 || list.Data[0].Region != "" {
		t.Fatalf("%+v %v", list, err)
	}
}

func TestRegionURLsAndDefaultRegion(t *testing.T) {
	eu := newMock(t)
	eu.json("GET /api/v1/sandbox/instances/e1", 200, `{"id":"e1","status":"running"}`)
	home := newMock(t)
	c := home.client(WithRegionURLs(map[string]string{"eu": eu.srv.URL}), WithDefaultRegion("eu"))
	sb, err := c.Sandboxes.Get(ctx(), "e1")
	if err != nil || sb.Region != "eu" || home.count() != 0 {
		t.Fatalf("%v %+v home=%d", err, sb, home.count())
	}
	// Explicit region URLs also decide which regions a list reads.
	eu.json("GET /api/v1/sandbox/instances", 200, `{"data":[{"id":"e1"}]}`)
	c = home.client(WithRegionURLs(map[string]string{"eu": eu.srv.URL}))
	list, err := c.Sandboxes.List(ctx(), ListSandboxesParams{})
	if err != nil || len(list.Data) != 1 || home.count() != 0 {
		t.Fatalf("%v %+v", err, list)
	}
}

func TestSandscaleFrontDoorRegions(t *testing.T) {
	c, err := NewClient(WithAPIKey("k"))
	if err != nil {
		t.Fatal(err)
	}
	for region, want := range map[string]string{"us": "https://api.us.sandscale.dev", "us1": "https://api.us.sandscale.dev", "EU": "https://api.eu.sandscale.dev", "eu1": "https://api.eu.sandscale.dev", "": DefaultBaseURL} {
		got, err := c.originFor(ctx(), region)
		if err != nil || got != want {
			t.Errorf("%q -> %q %v, want %q", region, got, err, want)
		}
	}
	if _, err := c.originFor(ctx(), "mars"); !errors.Is(err, ErrRegion) {
		t.Fatalf("unknown Sandscale region: %v", err)
	}
}

func TestExecWaits(t *testing.T) {
	m := newMock(t)
	m.json("POST /api/v1/sandbox/instances/sb1/exec", 200, `{"run_id":"r1","exit_code":3,"stdout":"hello\n","stderr":"oops\n","duration_ms":12,"oom_killed":false,"timed_out":true}`)
	res, err := m.client().Sandboxes.Exec(ctx(), "sb1", ExecParams{Shell: "echo hello", Env: map[string]string{"A": "b"}, Workdir: "/workspace/x", Stdin: []byte("in"), Timeout: 90 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 3 || res.Stdout != "hello\n" || res.Stderr != "oops\n" || res.RunID != "r1" || res.Duration != 12*time.Millisecond || !res.TimedOut || res.OOMKilled || res.Streamed {
		t.Fatalf("%+v", res)
	}
	body := bodyOf(t, m.last())
	if !reflect.DeepEqual(body["command"], []any{"sh", "-c", "echo hello"}) || body["timeout_sec"] != float64(90) || body["workdir"] != "/workspace/x" {
		t.Fatalf("body %v", body)
	}
	if body["stdin"] != base64.StdEncoding.EncodeToString([]byte("in")) {
		t.Fatalf("stdin is base64: %v", body["stdin"])
	}
	if _, has := body["wait"]; has {
		t.Fatal("a waiting exec does not send wait")
	}
	var ce *ConfigError
	if _, err := m.client().Sandboxes.Exec(ctx(), "sb1", ExecParams{}); !errors.As(err, &ce) {
		t.Fatalf("a missing command: %v", err)
	}
}

func sse(w http.ResponseWriter, events ...string) {
	w.Header().Set("Content-Type", "text/event-stream")
	for _, e := range events {
		fmt.Fprint(w, e)
		w.(http.Flusher).Flush()
	}
}

func TestExecStreamsLiveOutput(t *testing.T) {
	m := newMock(t)
	m.json("POST /api/v1/sandbox/instances/sb1/exec", 202, `{"run_id":"r9","status":"queued"}`)
	m.on("GET /api/v1/sandbox/instances/sb1/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("run_id") != "r9" || r.Header.Get("Accept") != "text/event-stream" {
			t.Errorf("logs request %s %v", r.URL.RawQuery, r.Header)
		}
		sse(w,
			"event: chunk\ndata: {\"stream\":\"stdout\",\"data\":\"hel\",\"chunk_index\":0}\n\n",
			"event: chunk\r\ndata: {\"stream\":\"stderr\",\"data\":\"err\",\"chunk_index\":1}\r\n\r\n",
			"event: chunk\ndata: {\"stream\":\"stdout\",\"data\":\"lo\",\"chunk_index\":2}\n\n",
			"event: done\ndata: {\"run_id\":\"r9\",\"status\":\"completed\",\"exit_code\":0,\"duration_ms\":40}\n\n")
	})
	var out, errOut []string
	res, err := m.client().Sandboxes.Exec(ctx(), "sb1", ExecParams{
		Command: []string{"echo", "hello"}, OnStdout: func(s string) { out = append(out, s) }, OnStderr: func(s string) { errOut = append(errOut, s) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, []string{"hel", "lo"}) || !reflect.DeepEqual(errOut, []string{"err"}) {
		t.Fatalf("live callbacks: %v %v", out, errOut)
	}
	if res.Stdout != "hello" || res.Stderr != "err" || res.ExitCode != 0 || !res.Streamed || res.RunID != "r9" || res.Duration != 40*time.Millisecond {
		t.Fatalf("%+v", res)
	}
	var execReq recorded
	m.mu.Lock()
	for _, r := range m.req {
		if r.Method == "POST" {
			execReq = r
		}
	}
	m.mu.Unlock()
	if bodyOf(t, execReq)["wait"] != false {
		t.Fatal("a live exec starts the command without waiting")
	}
}

func TestExecLiveWithFinishedAnswerAndReadsRun(t *testing.T) {
	m := newMock(t)
	// A server before `wait` answers with the finished result: callbacks get the final output once.
	m.json("POST /api/v1/sandbox/instances/sb1/exec", 200, `{"run_id":"r1","exit_code":0,"stdout":"final","stderr":""}`)
	var got []string
	res, err := m.client().Sandboxes.Exec(ctx(), "sb1", ExecParams{Shell: "x", OnStdout: func(s string) { got = append(got, s) }})
	if err != nil || res.Streamed || !reflect.DeepEqual(got, []string{"final"}) {
		t.Fatalf("%+v %v %v", res, got, err)
	}
	// A stream end without a result: the run is read.
	m.json("POST /api/v1/sandbox/instances/sb1/exec", 202, `{"run_id":"r2"}`)
	m.on("GET /api/v1/sandbox/instances/sb1/logs", func(w http.ResponseWriter, r *http.Request) {
		sse(w, "event: chunk\ndata: {\"stream\":\"stdout\",\"data\":\"x\",\"chunk_index\":0}\n\n", "event: done\ndata: {}\n\n")
	})
	m.json("GET /api/v1/sandbox/runs/r2", 200, `{"exit_code":7,"duration_ms":5,"oom_killed":true}`)
	res, err = m.client().Sandboxes.Exec(ctx(), "sb1", ExecParams{Shell: "x", OnStdout: func(string) {}})
	if err != nil || res.ExitCode != 7 || !res.OOMKilled || res.RunID != "r2" || res.Stdout != "x" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestStreamLogsResumesAfterDrop(t *testing.T) {
	m := newMock(t)
	conns := 0
	m.on("GET /api/v1/sandbox/instances/sb1/logs", func(w http.ResponseWriter, r *http.Request) {
		conns++
		if conns == 1 {
			if r.URL.Query().Get("from_chunk") != "" {
				t.Errorf("the first connection starts at the beginning")
			}
			sse(w, "event: chunk\ndata: {\"stream\":\"stdout\",\"data\":\"a\",\"chunk_index\":0}\n\n", "event: chunk\ndata: {\"stream\":\"stdout\",\"data\":\"b\",\"chunk_index\":1}\n\n")
			return // the connection ends without a done event
		}
		if r.URL.Query().Get("from_chunk") != "2" {
			t.Errorf("the reconnect resumes after the last chunk, got %q", r.URL.Query().Get("from_chunk"))
		}
		sse(w, "event: chunk\ndata: {\"stream\":\"stdout\",\"data\":\"c\",\"chunk_index\":2}\n\n", "event: done\ndata: {\"exit_code\":0}\n\n")
	})
	var got string
	end, err := m.client().Sandboxes.StreamLogs(ctx(), "sb1", "r1", func(c OutputChunk) error { got += c.Data; return nil })
	if err != nil || got != "abc" || end.ExitCode == nil || *end.ExitCode != 0 || conns != 2 {
		t.Fatalf("got %q end=%+v err=%v conns=%d", got, end, err, conns)
	}
}

func TestStreamLogsErrorEventAndCallbackError(t *testing.T) {
	m := newMock(t)
	m.on("GET /api/v1/sandbox/instances/sb1/logs", func(w http.ResponseWriter, r *http.Request) {
		sse(w, "event: chunk\ndata: {\"stream\":\"stdout\",\"data\":\"a\",\"chunk_index\":0}\n\n", "event: error\ndata: {\"code\":\"dlp_scan_failed\",\"message\":\"withheld\"}\n\n")
	})
	_, err := m.client().Sandboxes.StreamLogs(ctx(), "sb1", "r1", func(OutputChunk) error { return nil })
	api, ok := AsAPIError(err)
	if !ok || api.Code != "dlp_scan_failed" || !errors.Is(err, ErrServiceUnavailable) {
		t.Fatalf("an error event is never a silently cut output: %v", err)
	}
	stop := errors.New("stop reading")
	_, err = m.client().Sandboxes.StreamLogs(ctx(), "sb1", "r1", func(OutputChunk) error { return stop })
	if !errors.Is(err, stop) {
		t.Fatalf("the callback's error is returned: %v", err)
	}
	var calls int
	m.on("GET /api/v1/sandbox/instances/sb1/logs", func(w http.ResponseWriter, r *http.Request) { calls++; sse(w) })
	_, err = m.client().Sandboxes.StreamLogs(ctx(), "sb1", "r1", func(OutputChunk) error { return nil })
	var ce *ConnectionError
	if !errors.As(err, &ce) || calls != 4 {
		t.Fatalf("a stream that never ends properly gives up after 3 reconnects: %v calls=%d", err, calls)
	}
}

func TestFiles(t *testing.T) {
	m := newMock(t)
	m.json("PUT /api/v1/sandbox/instances/sb1/files", 200, `{}`)
	if err := m.client().Sandboxes.WriteFile(ctx(), "sb1", "/workspace/a.sh", []byte{0, 1, 2, 255}, WithFileMode("0755")); err != nil {
		t.Fatal(err)
	}
	body := bodyOf(t, m.last())
	if body["path"] != "/workspace/a.sh" || body["mode"] != "0755" || body["content"] != base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 255}) {
		t.Fatalf("%v", body)
	}
	m.json("GET /api/v1/sandbox/instances/sb1/files", 200, `{"type":"file","content":"`+base64.StdEncoding.EncodeToString([]byte("hi"))+`"}`)
	data, err := m.client().Sandboxes.ReadFile(ctx(), "sb1", "/workspace/a.txt")
	if err != nil || string(data) != "hi" || m.last().Query != "path=%2Fworkspace%2Fa.txt" {
		t.Fatalf("%q %v %s", data, err, m.last().Query)
	}
	if _, err := m.client().Sandboxes.ListFiles(ctx(), "sb1", "/workspace/a.txt"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("listing a file: %v", err)
	}
	m.json("GET /api/v1/sandbox/instances/sb1/files", 200, `{"type":"dir","entries":[{"name":"a","type":"file","size_bytes":3},{"name":"d","type":"dir"}]}`)
	list, err := m.client().Sandboxes.ListFiles(ctx(), "sb1", "/workspace")
	want := []FileEntry{{Path: "/workspace/a", Name: "a", Size: 3}, {Path: "/workspace/d", Name: "d", IsDir: true, Size: -1}}
	if err != nil || !reflect.DeepEqual(list, want) {
		t.Fatalf("%+v %v", list, err)
	}
	if _, err := m.client().Sandboxes.ReadFile(ctx(), "sb1", "/workspace"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("reading a directory: %v", err)
	}
}

func TestLifecycle(t *testing.T) {
	m := newMock(t)
	m.json("POST /api/v1/sandbox/instances/sb1/pause", 200, `{"id":"sb1","status":"paused"}`)
	m.json("POST /api/v1/sandbox/instances/sb1/resume", 200, `{"id":"sb1","status":"running"}`)
	m.json("DELETE /api/v1/sandbox/instances/sb1", 204, ``)
	m.json("POST /api/v1/sandbox/instances/ct/pause", 409, `{"error":{"code":"pause_unsupported","message":"container sandbox"}}`)
	c := m.client()
	if r, err := c.Sandboxes.Pause(ctx(), "sb1"); err != nil || r.Status != "paused" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := c.Sandboxes.Resume(ctx(), "sb1"); err != nil || r.Status != "running" {
		t.Fatalf("%+v %v", r, err)
	}
	if err := c.Sandboxes.Stop(ctx(), "sb1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sandboxes.Pause(ctx(), "ct"); !errors.Is(err, ErrConflict) {
		t.Fatalf("%v", err)
	}
}

func TestKeepAwakeRetriesWaking(t *testing.T) {
	m := newMock(t)
	n := 0
	m.on("POST /api/v1/sandbox/instances/sb1/keep-awake", func(w http.ResponseWriter, r *http.Request) {
		n++
		if n < 3 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(503)
			fmt.Fprint(w, `{"error":{"code":"sandbox_waking","message":"resuming"}}`)
			return
		}
		fmt.Fprint(w, `{"id":"sb1","keep_awake":true,"until":"2026-11-18T01:00:00Z","reason":"waiting","ttl_seconds":300}`)
	})
	res, err := m.client().Sandboxes.KeepAwake(ctx(), "sb1", KeepAwakeParams{TTLSeconds: 300, Reason: "waiting"})
	if err != nil || !res.KeepAwake || res.TTLSeconds != 300 || res.Until.IsZero() || n != 3 {
		t.Fatalf("%+v %v n=%d", res, err, n)
	}
	body := bodyOf(t, m.last())
	if body["ttl_seconds"] != float64(300) || body["reason"] != "waiting" {
		t.Fatalf("%v", body)
	}
	m.json("POST /api/v1/sandbox/instances/sb2/keep-awake", 503, `{"error":{"code":"sandbox_waking","message":"resuming"}}`)
	if _, err := m.client().Sandboxes.KeepAwake(ctx(), "sb2", KeepAwakeParams{}); !errors.Is(err, ErrSandboxWaking) {
		t.Fatalf("gives up after a few tries: %v", err)
	}
}

func TestSnapshots(t *testing.T) {
	m := newMock(t)
	m.json("POST /api/v1/sandbox/instances/sb1/snapshot", 201, `{"id":"s1","instance_id":"sb1","status":"creating","label":"before","size_bytes":0}`)
	m.json("GET /api/v1/sandbox/instances/sb1/snapshots", 200, `{"snapshots":[{"id":"s1","instance_id":"sb1","status":"ready","label":"before","size_bytes":2048,"sha256":"ab"}]}`)
	c := m.client()
	s, err := c.Sandboxes.Snapshot(ctx(), "sb1", SnapshotParams{Label: "before"})
	if err != nil || s.ID != "s1" || s.Status != "creating" || bodyOf(t, m.last())["label"] != "before" {
		t.Fatalf("%+v %v", s, err)
	}
	if _, err := c.Sandboxes.Snapshot(ctx(), "sb1", SnapshotParams{}); err != nil || len(m.last().Body) != 0 {
		t.Fatalf("no label sends no body: %q %v", m.last().Body, err)
	}
	list, err := c.Sandboxes.ListSnapshots(ctx(), "sb1")
	if err != nil || len(list) != 1 || list[0].SizeBytes != 2048 || list[0].SHA256 != "ab" {
		t.Fatalf("the server answers a snapshots field: %+v %v", list, err)
	}
	m.json("GET /api/v1/sandbox/snapshots", 200, `{"snapshots":[{"id":"s1","status":"ready"}],"usage":{"count":4,"bytes":9000}}`)
	m.json("GET /api/v1/sandbox/snapshots/s1", 200, `{"id":"s1","status":"ready"}`)
	m.json("DELETE /api/v1/sandbox/snapshots/s1", 204, ``)
	all, err := c.Snapshots.List(ctx(), ListSnapshotsParams{Limit: 10})
	if err != nil || len(all.Data) != 1 || all.Usage.Count != 4 || all.Usage.Bytes != 9000 {
		t.Fatalf("%+v %v", all, err)
	}
	if g, err := c.Snapshots.Get(ctx(), "s1"); err != nil || g.ID != "s1" {
		t.Fatalf("%+v %v", g, err)
	}
	if err := c.Snapshots.Delete(ctx(), "s1"); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaces(t *testing.T) {
	m := newMock(t)
	base := "/api/v1/orgs/org1/workspaces"
	m.json("POST "+base, 202, `{"workspace":{"id":"w1","name":"dev","status":"stopped","template_id":"t1"},"build":{"id":"b1","workspace_id":"w1","state":"pending","build_number":1}}`)
	m.json("GET "+base, 200, `{"workspaces":[{"id":"w1","name":"dev","status":"running","last_used_at":""}],"next_cursor":"n"}`)
	m.json("GET "+base+"/w1", 200, `{"id":"w1","name":"dev","status":"running","health":"ok"}`)
	m.json("PATCH "+base+"/w1", 200, `{"id":"w1","name":"renamed","status":"running"}`)
	m.json("DELETE "+base+"/w1", 204, ``)
	m.json("POST "+base+"/w1/start", 202, `{"id":"b2","workspace_id":"w1","state":"pending","desired_state":"running"}`)
	m.json("POST "+base+"/w1/stop", 202, `{"id":"b3","workspace_id":"w1","state":"pending"}`)
	m.json("POST "+base+"/w1/rebuild", 202, `{"id":"b4","workspace_id":"w1","state":"pending"}`)
	m.json("GET "+base+"/w1/connect", 200, `{"ssh_host":"w1.example","ssh_ready":true,"links":[{"ide":"vscode","kind":"deeplink","url":"vscode://x","requires":["config-ssh"]}]}`)
	m.json("GET "+base+"/w1/open", 200, `{"kind":"deeplink","url":"cursor://x","requires":[]}`)
	c := m.client()

	created, err := c.Workspaces.Create(ctx(), CreateWorkspaceParams{Name: "dev", TemplateID: "t1", Parameters: map[string]string{"cpu": "2"}, AutostartSchedule: "0 9 * * 1-5", Repository: "https://example.com/r.git"})
	if err != nil || created.Workspace.ID != "w1" || created.Build.ID != "b1" || created.Build.BuildNumber != 1 {
		t.Fatalf("%+v %v", created, err)
	}
	body := bodyOf(t, m.last())
	if body["name"] != "dev" || body["template_id"] != "t1" || body["autostart_schedule"] != "0 9 * * 1-5" || body["repository"] != "https://example.com/r.git" {
		t.Fatalf("%v", body)
	}
	if m.last().Org != "org1" {
		t.Fatal("X-Org-ID")
	}
	list, err := c.Workspaces.List(ctx(), ListWorkspacesParams{Limit: 2, All: true})
	if err != nil || len(list.Data) != 1 || !list.Pages[0].HasMore || list.Pages[0].NextCursor != "n" || !list.Data[0].LastUsedAt.IsZero() {
		t.Fatalf("%+v %v", list, err)
	}
	if got := m.last().Query; got != "all=true&limit=2" {
		t.Fatalf("query %q", got)
	}
	if w, err := c.Workspaces.Get(ctx(), "w1"); err != nil || w.Health != "ok" {
		t.Fatalf("%+v %v", w, err)
	}
	name := "renamed"
	ttl := 0
	if w, err := c.Workspaces.Update(ctx(), "w1", UpdateWorkspaceParams{Name: &name, TTLSeconds: &ttl}); err != nil || w.Name != "renamed" {
		t.Fatalf("%+v %v", w, err)
	}
	if body := bodyOf(t, m.last()); body["name"] != "renamed" || body["ttl_seconds"] != float64(0) || len(body) != 2 {
		t.Fatalf("an explicit zero is sent, unset members are not: %v", body)
	}
	if b, err := c.Workspaces.Start(ctx(), "w1"); err != nil || b.DesiredState != "running" {
		t.Fatalf("%+v %v", b, err)
	}
	if b, err := c.Workspaces.Stop(ctx(), "w1"); err != nil || b.ID != "b3" {
		t.Fatalf("%+v %v", b, err)
	}
	if b, err := c.Workspaces.Rebuild(ctx(), "w1", RebuildWorkspaceParams{TemplateVersionID: "v2"}); err != nil || b.ID != "b4" || bodyOf(t, m.last())["template_version_id"] != "v2" {
		t.Fatalf("%+v %v", b, err)
	}
	if ci, err := c.Workspaces.ConnectInfo(ctx(), "w1"); err != nil || !ci.SSHReady || len(ci.Links) != 1 || ci.Links[0].Requires[0] != "config-ssh" {
		t.Fatalf("%+v %v", ci, err)
	}
	if l, err := c.Workspaces.OpenLink(ctx(), "w1", "cursor"); err != nil || l.IDE != "cursor" || l.URL != "cursor://x" || m.last().Query != "ide=cursor" {
		t.Fatalf("%+v %v", l, err)
	}
	if err := c.Workspaces.Delete(ctx(), "w1"); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspacesNeedAnOrganization(t *testing.T) {
	t.Setenv("SANDSCALE_ORG_ID", "")
	m := newMock(t)
	c, _ := NewClient(WithAPIKey("k"), WithBaseURL(m.srv.URL))
	var ce *ConfigError
	if _, err := c.Workspaces.Get(ctx(), "w1"); !errors.As(err, &ce) || m.count() != 0 {
		t.Fatalf("%v", err)
	}
	m.json("GET /api/v1/sandbox/instances/x", 200, `{"id":"x"}`)
	if _, err := c.Sandboxes.Get(ctx(), "x"); err != nil || m.last().Org != "" {
		t.Fatalf("sandbox calls need no organization: %v", err)
	}
}

func TestWorkspaceEntitlementError(t *testing.T) {
	m := newMock(t)
	m.json("POST /api/v1/orgs/org1/workspaces", 403, `{"error":{"code":"feature_not_in_plan","message":"workspaces are not in the Free plan"}}`)
	_, err := m.client().Workspaces.Create(ctx(), CreateWorkspaceParams{Name: "a"})
	if !errors.Is(err, ErrEntitlement) {
		t.Fatal(err)
	}
	if api, _ := AsAPIError(err); api.Message != "workspaces are not in the Free plan" {
		t.Fatal(api.Message)
	}
}

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestWebhooks(t *testing.T) {
	m := newMock(t)
	m.json("POST /api/v1/sandbox/webhooks", 201, `{"id":"wh1","url":"https://example.com/hook","events":["run.completed"],"active":true,"secret":"whsec_abc"}`)
	m.json("GET /api/v1/sandbox/webhooks", 200, `{"webhooks":[{"id":"wh1","url":"https://example.com/hook","events":["run.completed"],"active":true}]}`)
	m.json("DELETE /api/v1/sandbox/webhooks/wh1", 204, ``)
	c := m.client()
	wh, err := c.Webhooks.Create(ctx(), CreateWebhookParams{URL: "https://example.com/hook", Events: []string{EventRunCompleted}})
	if err != nil || wh.ID != "wh1" || wh.Secret() != "whsec_abc" || !wh.Active {
		t.Fatalf("%+v %v", wh, err)
	}
	for name, s := range map[string]string{"String": wh.String(), "Sprintf": fmt.Sprintf("%v %+v", wh, wh), "Raw": string(wh.Raw)} {
		if strings.Contains(s, "whsec_abc") {
			t.Errorf("%s leaks the secret: %s", name, s)
		}
	}
	list, err := c.Webhooks.List(ctx())
	if err != nil || len(list) != 1 || list[0].Events[0] != "run.completed" {
		t.Fatalf("%+v %v", list, err)
	}
	if err := c.Webhooks.Delete(ctx(), "wh1"); err != nil {
		t.Fatal(err)
	}
}

func TestVerifySignature(t *testing.T) {
	body := []byte(`{"event":"run.completed","id":"r1"}`)
	good := sign("whsec_abc", body)
	if !VerifySignature(good, body, "whsec_abc") || !VerifySignature(good[:7]+strings.ToUpper(good[7:]), body, "whsec_abc") {
		t.Fatal("a valid signature must verify (hex case does not matter)")
	}
	bad := map[string][3]any{
		"wrong secret":  {good, body, "other"},
		"changed body":  {good, []byte(`{"event":"run.completed","id":"r2"}`), "whsec_abc"},
		"empty header":  {"", body, "whsec_abc"},
		"no prefix":     {good[7:], body, "whsec_abc"},
		"empty secret":  {sign("", body), body, ""},
		"truncated mac": {good[:len(good)-2], body, "whsec_abc"},
		"not hex":       {"sha256=" + strings.Repeat("zz", 32), body, "whsec_abc"},
		"too long":      {good + "00", body, "whsec_abc"},
		"sha1 prefix":   {"sha1=" + good[7:], body, "whsec_abc"},
	}
	for name, a := range bad {
		if VerifySignature(a[0].(string), a[1].([]byte), a[2].(string)) {
			t.Errorf("%s must not verify", name)
		}
	}
}

func TestVerifyRequest(t *testing.T) {
	body := `{"event":"instance.created"}`
	mk := func(sig string, b string) *http.Request {
		r := httptest.NewRequest("POST", "/hook", strings.NewReader(b))
		if sig != "" {
			r.Header.Set(SignatureHeader, sig)
		}
		return r
	}
	got, err := VerifyRequest(mk(sign("s", []byte(body)), body), "s")
	if err != nil || string(got) != body {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := VerifyRequest(mk("", body), "s"); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("%v", err)
	}
	if _, err := VerifyRequest(mk(sign("s", []byte(body)), body+" "), "s"); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("%v", err)
	}
	big := strings.Repeat("x", MaxWebhookBody+1)
	if _, err := VerifyRequest(mk(sign("s", []byte(big)), big), "s"); err == nil {
		t.Fatal("an oversize body is refused")
	}
}

func TestTemplatesAndPolicy(t *testing.T) {
	m := newMock(t)
	m.json("POST /api/v1/sandbox/templates", 201, `{"id":"t1","name":"py","version":"0.1.0","status":"building","image":"x@sha256:aa","cpu_count":2}`)
	m.json("GET /api/v1/sandbox/templates", 200, `{"data":[{"id":"t1","name":"py","version":"0.1.0","status":"ready"}],"has_more":false}`)
	m.json("GET /api/v1/sandbox/templates/t1", 200, `{"id":"t1","name":"py","version":"0.1.0","status":"ready"}`)
	m.json("GET /api/v1/sandbox/templates/t1/build-status", 200, `{"status":"building","progress_percent":42.5}`)
	m.json("DELETE /api/v1/sandbox/templates/t1", 204, ``)
	c := m.client()
	tp, err := c.Templates.Create(ctx(), CreateTemplateParams{Name: "py", Image: "x@sha256:aa", CPUCount: 2})
	if err != nil || tp.Status != "building" || tp.CPUCount != 2 || bodyOf(t, m.last())["image"] != "x@sha256:aa" {
		t.Fatalf("%+v %v", tp, err)
	}
	if l, err := c.Templates.List(ctx()); err != nil || len(l.Data) != 1 {
		t.Fatalf("%+v %v", l, err)
	}
	if g, err := c.Templates.Get(ctx(), "t1"); err != nil || g.Status != "ready" {
		t.Fatalf("%+v %v", g, err)
	}
	if b, err := c.Templates.BuildStatus(ctx(), "t1"); err != nil || b.ProgressPercent != 42.5 {
		t.Fatalf("%+v %v", b, err)
	}
	if err := c.Templates.Delete(ctx(), "t1"); err != nil {
		t.Fatal(err)
	}

	m.json("GET /api/v1/sandbox/policy", 200, `{"max_concurrent":5,"max_exec_time_sec":600,"max_mem_mb":2048,"max_cpu":2,"max_disk_mb":null,"egress_allowlist":["example.com"],"hibernation":"on"}`)
	m.json("PUT /api/v1/sandbox/policy", 200, `{"max_concurrent":8,"max_exec_time_sec":600,"max_mem_mb":2048,"max_cpu":2,"max_disk_mb":10240,"hibernation":"off"}`)
	p, err := c.Policy.Get(ctx())
	if err != nil || p.MaxConcurrent != 5 || p.MaxDiskMB != nil || p.EgressAllowlist[0] != "example.com" || p.Hibernation != "on" {
		t.Fatalf("%+v %v", p, err)
	}
	n := 8
	p, err = c.Policy.Set(ctx(), SandboxPolicyUpdate{MaxConcurrent: &n, Hibernation: "off"})
	if err != nil || p.MaxConcurrent != 8 || *p.MaxDiskMB != 10240 {
		t.Fatalf("%+v %v", p, err)
	}
	// Unset lists are null (the server leaves them alone); an empty list clears it.
	if body := bodyOf(t, m.last()); len(body) != 5 || body["max_concurrent"] != float64(8) || body["hibernation"] != "off" || body["egress_allowlist"] != nil {
		t.Fatalf("members you did not set are not changed: %v", body)
	}
	if _, err := c.Policy.Set(ctx(), SandboxPolicyUpdate{EgressAllowlist: []string{}}); err != nil {
		t.Fatal(err)
	}
	if got := bodyOf(t, m.last())["egress_allowlist"]; !reflect.DeepEqual(got, []any{}) {
		t.Fatalf("an empty list is sent as [] so it clears the list: %v", got)
	}
}

func TestUsageAndRegions(t *testing.T) {
	m := newMock(t)
	m.json("GET /api/v1/sandscale/usage", 200, `{"month":"2026-11","vcpu_seconds_used":3600.5,"vcpu_seconds_left":7200,"running_boxes":2,"running_by_region":{"us1":1,"eu1":1}}`)
	m.json("GET /api/v1/regions", 200, `{"regions":[{"id":"us1","status":"live","api_url":"https://api.us.sandscale.dev"},{"id":"eu1","status":"coming_soon"}]}`)
	c := m.client()
	u, err := c.Account.Usage(ctx())
	if err != nil || u.Month != "2026-11" || u.VCPUSecondsUsed != 3600.5 || u.RunningBoxes != 2 || u.RunningByRegion["eu1"] != 1 {
		t.Fatalf("%+v %v", u, err)
	}
	regions, err := c.Account.Regions(ctx())
	if err != nil || len(regions) != 2 || regions[0].APIURL == "" || regions[1].Status != "coming_soon" {
		t.Fatalf("%+v %v", regions, err)
	}
	if r := m.last(); r.Auth != "" || r.Org != "" {
		t.Fatalf("the region list is public, no credential or organization is sent: %+v", r)
	}
}

func TestErrorTypesAreComparable(t *testing.T) {
	var e error = &APIError{Status: 429, Code: "rate_limited", Kind: KindRateLimited, RetryAfter: 2 * time.Second}
	wrapped := fmt.Errorf("listing: %w", e)
	api, ok := AsAPIError(wrapped)
	if !ok || api.RetryAfter != 2*time.Second || !api.Retryable() {
		t.Fatal("AsAPIError sees through wrapping")
	}
	if !errors.Is(wrapped, ErrRateLimited) || !errors.Is(wrapped, ErrLimitExceeded) || errors.Is(wrapped, ErrNotFound) {
		t.Fatal("sentinels")
	}
	if (&APIError{Status: 503, Code: "kill_switch_engaged", Kind: KindKillSwitch}).Retryable() {
		t.Fatal("a kill switch is not retryable")
	}
	if (&APIError{Status: 409, Kind: KindConflict}).Retryable() {
		t.Fatal("a conflict is not retryable")
	}
	for k := KindUnknown; k <= KindSandboxWaking; k++ {
		if k.String() == "" {
			t.Errorf("kind %d has no name", k)
		}
	}
	if !strings.Contains(ErrNotFound.Error(), "not found") {
		t.Fatal(ErrNotFound.Error())
	}
}

func TestParseEvent(t *testing.T) {
	e, err := ParseEvent([]byte(`{"id":"d1","type":"run.completed","org_id":"org1","occurred_at":"2026-11-18T01:02:03Z","data":{"run_id":"r1"}}`))
	if err != nil || e.ID != "d1" || e.Type != EventRunCompleted || e.OccurredAt.Year() != 2026 || string(e.Data) != `{"run_id":"r1"}` {
		t.Fatalf("%+v %v", e, err)
	}
	if _, err := ParseEvent([]byte(`nope`)); err == nil {
		t.Fatal("a garbled body is an error")
	}
}

func TestStreamLogsLongRunReconnectsWhilePrintingProgress(t *testing.T) {
	m := newMock(t)
	conns := 0
	m.on("GET /api/v1/sandbox/instances/sb1/logs", func(w http.ResponseWriter, r *http.Request) {
		conns++
		if conns <= 6 { // an idle-timeout proxy closes the connection after every chunk
			sse(w, fmt.Sprintf("event: chunk\ndata: {\"stream\":\"stdout\",\"data\":\"%d\",\"chunk_index\":%d}\n\n", conns, conns-1))
			return
		}
		sse(w, "event: done\ndata: {\"exit_code\":0}\n\n")
	})
	var got string
	end, err := m.client().Sandboxes.StreamLogs(ctx(), "sb1", "r1", func(c OutputChunk) error { got += c.Data; return nil })
	if err != nil || got != "123456" || end == nil || conns != 7 {
		t.Fatalf("got %q end=%+v err=%v conns=%d", got, end, err, conns)
	}
}

func TestWriteEmptyFile(t *testing.T) {
	m := newMock(t)
	m.json("PUT /api/v1/sandbox/instances/sb1/files", 200, `{}`)
	if err := m.client().Sandboxes.WriteFile(ctx(), "sb1", "/workspace/empty", nil); err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, m.last()); body["content"] != "" {
		t.Fatalf("an empty file is an empty string, not null: %v", body)
	}
}
