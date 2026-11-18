// Copyright 2026 Neural Inverse
// SPDX-License-Identifier: Apache-2.0

package sandscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recorded is one request the test server saw.
type recorded struct {
	Method, Path, Query, Auth, Org, UA, Accept string
	Body                                       []byte
}

type mock struct {
	t   *testing.T
	srv *httptest.Server
	mu  sync.Mutex
	req []recorded
	h   map[string]http.HandlerFunc // "METHOD /path"
}

func newMock(t *testing.T) *mock {
	m := &mock{t: t, h: map[string]http.HandlerFunc{}}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		logRoute(r.Method, r.URL.EscapedPath())
		m.mu.Lock()
		m.req = append(m.req, recorded{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, r.Header.Get("Authorization"), r.Header.Get("X-Org-ID"), r.Header.Get("User-Agent"), r.Header.Get("Accept"), body})
		h := m.h[r.Method+" "+r.URL.EscapedPath()]
		m.mu.Unlock()
		if h == nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":{"code":"not_found","message":"no such route in the test"}}`)
			return
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		h(w, r)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mock) on(route string, h http.HandlerFunc) { m.mu.Lock(); m.h[route] = h; m.mu.Unlock() }

func (m *mock) json(route string, status int, body string) {
	m.on(route, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	})
}

func (m *mock) last() recorded { m.mu.Lock(); defer m.mu.Unlock(); return m.req[len(m.req)-1] }
func (m *mock) count() int     { m.mu.Lock(); defer m.mu.Unlock(); return len(m.req) }

func (m *mock) client(opts ...Option) *Client {
	m.t.Helper()
	all := append([]Option{WithAPIKey("sk_test_123"), WithBaseURL(m.srv.URL), WithOrgID("org1")}, opts...)
	c, err := NewClient(all...)
	if err != nil {
		m.t.Fatal(err)
	}
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return c
}

func bodyOf(t *testing.T, r recorded) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("body %q: %v", r.Body, err)
	}
	return m
}

func TestConfiguration(t *testing.T) {
	t.Setenv("SANDSCALE_API_KEY", "")
	t.Setenv("SANDSCALE_BASE_URL", "")
	t.Setenv("SANDSCALE_ORG_ID", "")
	bad := map[string][]Option{
		"no credential":      {},
		"both credentials":   {WithAPIKey("k"), WithTokenSource(func(context.Context) (string, error) { return "t", nil })},
		"http remote":        {WithAPIKey("k"), WithBaseURL("http://api.example.com")},
		"credentials in url": {WithAPIKey("k"), WithBaseURL("https://u:p@api.example.com")},
		"query in url":       {WithAPIKey("k"), WithBaseURL("https://api.example.com?x=1")},
		"relative url":       {WithAPIKey("k"), WithBaseURL("api.example.com")},
		"bad region url":     {WithAPIKey("k"), WithRegionURLs(map[string]string{"us": "http://remote.example.com"})},
	}
	for name, opts := range bad {
		_, err := NewClient(opts...)
		var ce *ConfigError
		if !errors.As(err, &ce) {
			t.Errorf("%s: want *ConfigError, got %v", name, err)
		}
	}
	c, err := NewClient(WithAPIKey("k"))
	if err != nil || c.BaseURL() != DefaultBaseURL {
		t.Fatalf("default base URL: %v %v", c, err)
	}
	for _, u := range []string{"http://localhost:8080", "http://127.0.0.1:1", "http://[::1]:2"} {
		if _, err := NewClient(WithAPIKey("k"), WithBaseURL(u)); err != nil {
			t.Errorf("%s should be allowed: %v", u, err)
		}
	}
	t.Setenv("SANDSCALE_API_KEY", "from-env")
	t.Setenv("SANDSCALE_ORG_ID", "envorg")
	if c, err = NewClient(); err != nil || c.orgID != "envorg" {
		t.Fatalf("env config: %v", err)
	}
}

func TestRequestHeadersAndTokenSource(t *testing.T) {
	m := newMock(t)
	m.json("GET /api/v1/sandbox/instances/sb1", 200, `{"id":"sb1","status":"running"}`)
	c := m.client()
	if _, err := c.Sandboxes.Get(context.Background(), "sb1"); err != nil {
		t.Fatal(err)
	}
	r := m.last()
	if r.Auth != "Bearer sk_test_123" || r.Org != "org1" || r.Accept != "application/json" || !strings.HasPrefix(r.UA, "sandscale-sdk-go/"+Version) {
		t.Fatalf("headers: %+v", r)
	}
	n := 0
	c2, _ := NewClient(WithBaseURL(m.srv.URL), WithTokenSource(func(context.Context) (string, error) { n++; return fmt.Sprintf("tok%d", n), nil }))
	for i := 0; i < 2; i++ {
		if _, err := c2.Sandboxes.Get(context.Background(), "sb1"); err != nil {
			t.Fatal(err)
		}
	}
	if m.last().Auth != "Bearer tok2" {
		t.Fatalf("the token source is called before every request: %q", m.last().Auth)
	}
	c3, _ := NewClient(WithBaseURL(m.srv.URL), WithTokenSource(func(context.Context) (string, error) { return " ", nil }))
	var ce *ConfigError
	if _, err := c3.Sandboxes.Get(context.Background(), "sb1"); !errors.As(err, &ce) {
		t.Fatalf("empty token: %v", err)
	}
}

func TestEmptyAndEscapedIDs(t *testing.T) {
	m := newMock(t)
	m.json("GET /api/v1/sandbox/instances/a%2Fb", 200, `{"id":"a/b"}`)
	c := m.client()
	var ce *ConfigError
	if _, err := c.Sandboxes.Get(context.Background(), ""); !errors.As(err, &ce) {
		t.Fatalf("empty id: %v", err)
	}
	if m.count() != 0 {
		t.Fatal("an empty id must not reach the network")
	}
	// A slash in an id stays inside its path segment: it can never reach another route.
	sb, err := c.Sandboxes.Get(context.Background(), "a/b")
	if err != nil || sb.ID != "a/b" {
		t.Fatalf("%+v %v", sb, err)
	}
	if got := m.last().Path; got != "/api/v1/sandbox/instances/a%2Fb" {
		t.Fatalf("path %q", got)
	}
}

func TestErrorKinds(t *testing.T) {
	cases := []struct {
		status int
		code   string
		sent   []error
		not    []error
	}{
		{400, "invalid_request", []error{ErrInvalidRequest}, []error{ErrServer}},
		{422, "bad_field", []error{ErrInvalidRequest}, nil},
		{413, "too_large", []error{ErrInvalidRequest}, nil},
		{401, "unauthorized", []error{ErrAuthentication}, nil},
		{403, "forbidden", []error{ErrPermissionDenied}, []error{ErrEntitlement}},
		{404, "not_found", []error{ErrNotFound}, nil},
		{409, "pause_unsupported", []error{ErrConflict}, nil},
		{402, "payment_required", []error{ErrEntitlement}, []error{ErrLimitExceeded}},
		{403, "feature_not_in_plan", []error{ErrEntitlement}, []error{ErrPermissionDenied}},
		{403, "public_preview_not_in_plan", []error{ErrEntitlement}, nil},
		{403, "plan_required", []error{ErrEntitlement}, nil},
		{429, "rate_limited", []error{ErrRateLimited, ErrLimitExceeded}, []error{ErrServer}},
		{403, "quota_exceeded", []error{ErrLimitExceeded}, []error{ErrRateLimited}},
		{409, "concurrent_limit", []error{ErrLimitExceeded}, nil},
		{402, "something_else", []error{ErrLimitExceeded}, nil},
		{403, "kill_switch_engaged", []error{ErrKillSwitch}, []error{ErrPermissionDenied}},
		{503, "org_kill_switch", []error{ErrKillSwitch}, []error{ErrServiceUnavailable}},
		{421, "wrong_region", []error{ErrRegion}, nil},
		{503, "region_unavailable", []error{ErrRegion}, nil},
		{503, "sandbox_waking", []error{ErrSandboxWaking, ErrServiceUnavailable, ErrServer}, nil},
		{503, "entitlement_unavailable", []error{ErrServiceUnavailable, ErrServer}, []error{ErrEntitlement}},
		{503, "overloaded", []error{ErrServiceUnavailable, ErrServer}, []error{ErrSandboxWaking}},
		{500, "internal_error", []error{ErrServer}, []error{ErrServiceUnavailable}},
		{502, "bad_gateway", []error{ErrServer}, nil},
		// Codes the Sandscale sandbox API sends, with the status it sends them with.
		{409, "snapshot_quota_exceeded", []error{ErrLimitExceeded}, nil},
		{409, "port_exposure_limit", []error{ErrLimitExceeded}, nil},
		{409, "preview_link_limit", []error{ErrLimitExceeded}, nil},
		{429, "queue_full", []error{ErrRateLimited, ErrLimitExceeded}, nil},
		{503, "tunnel_limit", []error{ErrLimitExceeded}, nil},
		{403, "network_not_in_plan", []error{ErrEntitlement}, nil},
		{409, "instance_paused", []error{ErrConflict}, []error{ErrLimitExceeded}},
		{409, "pause_unsupported", []error{ErrConflict}, nil},
		{503, "audit_unavailable", []error{ErrServiceUnavailable}, nil},
		{503, "snapshots_unavailable", []error{ErrServiceUnavailable}, nil},
		{400, "vault_env_refused", []error{ErrInvalidRequest}, nil},
		{400, "runtime_not_available", []error{ErrInvalidRequest}, nil},
		{404, "snapshot_not_found", []error{ErrNotFound}, nil},
	}
	for _, tc := range cases {
		m := newMock(t)
		m.json("GET /api/v1/sandbox/instances/x", tc.status, fmt.Sprintf(`{"error":{"code":%q,"message":"msg","request_id":"req-1","detail":{"k":1}}}`, tc.code))
		_, err := m.client(WithMaxRetries(0)).Sandboxes.Get(context.Background(), "x")
		api, ok := AsAPIError(err)
		if !ok {
			t.Fatalf("%d %s: not an *APIError: %v", tc.status, tc.code, err)
		}
		if api.Status != tc.status || api.Code != tc.code || api.Message != "msg" || api.RequestID != "req-1" || string(api.Details) != `{"k":1}` {
			t.Errorf("%d %s: fields %+v", tc.status, tc.code, api)
		}
		for _, want := range tc.sent {
			if !errors.Is(err, want) {
				t.Errorf("%d %s: should match %v (kind %v)", tc.status, tc.code, want, api.Kind)
			}
		}
		for _, no := range tc.not {
			if errors.Is(err, no) {
				t.Errorf("%d %s: must not match %v", tc.status, tc.code, no)
			}
		}
	}
}

func TestErrorEnvelopeVariants(t *testing.T) {
	e := parseError(421, "Misdirected", []byte(`{"code":"wrong_region","message":"use eu","region":"eu1"}`), http.Header{"X-Request-Id": {"hdr-1"}}, time.Unix(0, 0))
	if e.Code != "wrong_region" || e.Region != "eu1" || e.RequestID != "hdr-1" || e.Kind != KindRegion {
		t.Fatalf("top-level wrong_region: %+v", e)
	}
	e = parseError(500, "Internal Server Error", []byte(`<html>oops</html>`), http.Header{}, time.Unix(0, 0))
	if e.Code != "http_500" || e.Message != "Internal Server Error" || e.Kind != KindServer {
		t.Fatalf("non-JSON body: %+v", e)
	}
	e = parseError(400, "Bad Request", []byte(`{"error":"plain string"}`), http.Header{}, time.Unix(0, 0))
	if e.Code != "http_400" || e.Kind != KindInvalidRequest {
		t.Fatalf("string error: %+v", e)
	}
	e = parseError(409, "", []byte(`{"error":{"code":"x","message":"m","details":[1,2]}}`), http.Header{}, time.Unix(0, 0))
	if string(e.Details) != "[1,2]" {
		t.Fatalf("details: %+v", e)
	}
	if !strings.Contains(e.Error(), "m") || !strings.Contains(e.Error(), "409") {
		t.Fatalf("Error(): %s", e.Error())
	}
	if e := parseError(399, "x", nil, http.Header{}, time.Unix(0, 0)); e.Kind != KindUnknown {
		t.Fatalf("unexpected status: %+v", e)
	}
}

func TestRetryAfterParsing(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	if d := parseRetryAfter("3", now); d != 3*time.Second {
		t.Fatal(d)
	}
	if d := parseRetryAfter("0.5", now); d != 500*time.Millisecond {
		t.Fatal(d)
	}
	if d := parseRetryAfter(now.Add(10*time.Second).Format(http.TimeFormat), now); d != 10*time.Second {
		t.Fatal(d)
	}
	for _, bad := range []string{"", "soon", "-4", now.Add(-time.Hour).Format(http.TimeFormat)} {
		if d := parseRetryAfter(bad, now); d != 0 {
			t.Fatalf("%q -> %v", bad, d)
		}
	}
}

func TestRetriesSafeCallsOnly(t *testing.T) {
	m := newMock(t)
	var gets atomic.Int32
	m.on("GET /api/v1/sandbox/instances/x", func(w http.ResponseWriter, r *http.Request) {
		if gets.Add(1) < 3 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(503)
			fmt.Fprint(w, `{"error":{"code":"overloaded","message":"busy"}}`)
			return
		}
		fmt.Fprint(w, `{"id":"x","status":"running"}`)
	})
	var slept []time.Duration
	c := m.client()
	c.sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	sb, err := c.Sandboxes.Get(context.Background(), "x")
	if err != nil || sb.ID != "x" || gets.Load() != 3 {
		t.Fatalf("a GET is retried: %v gets=%d", err, gets.Load())
	}
	if len(slept) != 2 || slept[0] != time.Second {
		t.Fatalf("Retry-After is honoured: %v", slept)
	}

	var posts atomic.Int32
	m.on("POST /api/v1/sandbox/instances", func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		w.WriteHeader(503)
		fmt.Fprint(w, `{"error":{"code":"overloaded","message":"busy"}}`)
	})
	if _, err := c.Sandboxes.Create(context.Background(), CreateSandboxParams{}); !errors.Is(err, ErrServiceUnavailable) {
		t.Fatal(err)
	}
	if posts.Load() != 1 {
		t.Fatalf("a POST is sent once, got %d", posts.Load())
	}

	// Kill switch, entitlement and region refusals are never retried.
	for _, code := range []string{"kill_switch_engaged", "not_entitled", "wrong_region"} {
		var n atomic.Int32
		m.on("GET /api/v1/sandbox/instances/y", func(w http.ResponseWriter, r *http.Request) {
			n.Add(1)
			w.WriteHeader(503)
			fmt.Fprintf(w, `{"error":{"code":%q,"message":"no"}}`, code)
		})
		_, _ = c.Sandboxes.Get(context.Background(), "y")
		if n.Load() != 1 {
			t.Errorf("%s was retried %d times", code, n.Load())
		}
	}
	// WithMaxRetries(0) disables retries.
	var n atomic.Int32
	m.on("GET /api/v1/sandbox/instances/z", func(w http.ResponseWriter, r *http.Request) { n.Add(1); w.WriteHeader(502) })
	_, _ = m.client(WithMaxRetries(0)).Sandboxes.Get(context.Background(), "z")
	if n.Load() != 1 {
		t.Fatalf("retries disabled: %d", n.Load())
	}
}

func TestRedirectsAreRefused(t *testing.T) {
	var hit atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Add(1)
		fmt.Fprint(w, `{"id":"x"}`)
	}))
	defer target.Close()
	m := newMock(t)
	m.on("GET /api/v1/sandbox/instances/x", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/steal", http.StatusFound)
	})
	_, err := m.client(WithMaxRetries(0)).Sandboxes.Get(context.Background(), "x")
	if err == nil || hit.Load() != 0 {
		t.Fatalf("a redirect must never be followed (err=%v, hits=%d)", err, hit.Load())
	}
	// A caller's own HTTP client keeps its settings but loses its redirect policy.
	own := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
	_, err = m.client(WithHTTPClient(own), WithMaxRetries(0)).Sandboxes.Get(context.Background(), "x")
	if err == nil || hit.Load() != 0 {
		t.Fatalf("a custom HTTP client must not follow redirects either (err=%v, hits=%d)", err, hit.Load())
	}
}

func TestConnectionErrorsAndContext(t *testing.T) {
	m := newMock(t)
	c := m.client(WithMaxRetries(0))
	m.srv.Close()
	_, err := c.Sandboxes.Get(context.Background(), "x")
	var ce *ConnectionError
	if !errors.As(err, &ce) {
		t.Fatalf("want *ConnectionError, got %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m2 := newMock(t)
	m2.json("GET /api/v1/sandbox/instances/x", 200, `{}`)
	if _, err := m2.client().Sandboxes.Get(ctx, "x"); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled context is returned as is: %v", err)
	}
}

func TestTimeout(t *testing.T) {
	m := newMock(t)
	release := make(chan struct{})
	m.on("GET /api/v1/sandbox/instances/x", func(w http.ResponseWriter, r *http.Request) { <-release })
	defer close(release)
	c := m.client(WithTimeout(50*time.Millisecond), WithMaxRetries(0))
	_, err := c.Sandboxes.Get(context.Background(), "x")
	var ce *ConnectionError
	if !errors.As(err, &ce) || !strings.Contains(ce.Op, "timed out") {
		t.Fatalf("want a timed out ConnectionError, got %v", err)
	}
}

func TestTimeLenient(t *testing.T) {
	var s Sandbox
	if err := json.Unmarshal([]byte(`{"id":"a","created_at":"2026-11-18T01:02:03Z","started_at":"","terminated_at":null}`), &s); err != nil {
		t.Fatal(err)
	}
	if s.CreatedAt.Year() != 2026 || !s.StartedAt.IsZero() || !s.TerminatedAt.IsZero() {
		t.Fatalf("%+v", s)
	}
	if err := json.Unmarshal([]byte(`{"created_at":"yesterday"}`), &s); err == nil {
		t.Fatal("a garbled timestamp must be an error")
	}
	b, _ := json.Marshal(Time{})
	if string(b) != "null" {
		t.Fatal(string(b))
	}
}
