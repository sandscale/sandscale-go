// Copyright 2026 Neural Inverse
// SPDX-License-Identifier: Apache-2.0

package sandscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultBaseURL is the Sandscale API front door. It routes a request to its region, US by default.
const DefaultBaseURL = "https://api.sandscale.dev"

const frontDoorHost = "api.sandscale.dev"

// regionURLs are Sandscale's regional APIs. A region id such as "us1" names the same region as "us".
var regionURLs = map[string]string{
	"us": "https://api.us.sandscale.dev",
	"eu": "https://api.eu.sandscale.dev",
}

const (
	regionListTTL   = time.Minute
	maxBackoff      = 8 * time.Second
	maxRetryAfter   = time.Minute
	maxErrorBody    = 1 << 20
	maxResponseBody = 256 << 20
)

var trailingDigits = regexp.MustCompile(`\d+$`)

func sandscaleRegion(region string) string {
	return trailingDigits.ReplaceAllString(strings.ToLower(region), "")
}

// Client talks to the Sandscale API. It is safe for concurrent use.
type Client struct {
	// Sandboxes starts, runs and stops sandboxes.
	Sandboxes *SandboxesService
	// Workspaces manages cloud workspaces (needs an organization id).
	Workspaces *WorkspacesService
	// Webhooks manages webhook endpoints for sandbox events and verifies their signatures.
	Webhooks *WebhooksService
	// Snapshots manages the organization's sandbox snapshots.
	Snapshots *SnapshotsService
	// Templates manages sandbox templates.
	Templates *TemplatesService
	// Policy reads and changes the organization's sandbox policy.
	Policy *PolicyService
	// Account reads usage and the region list.
	Account *AccountService

	baseURL    string
	front      bool
	orgID      string
	region     string
	credential func(context.Context) (string, error)
	regionURLs map[string]string
	hc         *http.Client
	timeout    time.Duration
	maxRetries int
	userAgent  string

	sleep func(context.Context, time.Duration) error
	now   func() time.Time

	mu           sync.Mutex
	regionList   []regionEntry
	regionListAt time.Time
}

type config struct {
	apiKey     string
	hasKey     bool
	token      func(context.Context) (string, error)
	baseURL    string
	orgID      string
	region     string
	regionURLs map[string]string
	hc         *http.Client
	timeout    time.Duration
	maxRetries int
	retriesSet bool
}

// Option configures NewClient.
type Option func(*config)

// WithAPIKey sets a Sandscale API key. Default: $SANDSCALE_API_KEY. Give this or a token source.
func WithAPIKey(key string) Option { return func(c *config) { c.apiKey, c.hasKey = key, true } }

// WithTokenSource sets the person's own sign-in access token source. It is called before every
// request, so it can return a refreshed token.
func WithTokenSource(f func(ctx context.Context) (string, error)) Option {
	return func(c *config) { c.token = f }
}

// WithBaseURL sets the API origin. Default: $SANDSCALE_BASE_URL, else https://api.sandscale.dev.
// It must be https (plain http only to a loopback host).
func WithBaseURL(u string) Option { return func(c *config) { c.baseURL = u } }

// WithOrgID sets the organization id, sent as X-Org-ID and required by workspace calls.
// Default: $SANDSCALE_ORG_ID.
func WithOrgID(id string) Option { return func(c *config) { c.orgID = id } }

// WithRegion sends one call to a region ("us" or "eu"; "us1" names the same as "us"). It overrides
// the client's default region (WithDefaultRegion). Resources report the region they live in, so
// later calls on them pass WithRegion(resource.Region).
func WithRegion(region string) CallOption { return func(c *callConfig) { c.region = region } }

// WithDefaultRegion sets the client's default region, used by every call that does not name one.
func WithDefaultRegion(region string) Option { return func(c *config) { c.region = region } }

// WithRegionURLs sets an explicit API URL per region, instead of the built-in Sandscale regions
// or the server's public region list.
func WithRegionURLs(m map[string]string) Option { return func(c *config) { c.regionURLs = m } }

// WithHTTPClient sets the HTTP client. The client's redirect policy is replaced: a redirect is
// never followed, so a credential never follows one.
func WithHTTPClient(hc *http.Client) Option { return func(c *config) { c.hc = hc } }

// WithTimeout sets the per-request timeout of calls that wait for an answer (default 60s).
func WithTimeout(d time.Duration) Option { return func(c *config) { c.timeout = d } }

// WithMaxRetries sets how often a safe (GET) call is retried after a connection error, 429, 502,
// 503 or 504 (default 2; 0 disables retries).
func WithMaxRetries(n int) Option {
	return func(c *config) { c.maxRetries, c.retriesSet = n, true }
}

// NewClient builds a client. It returns a *ConfigError when no credential is given or the base
// URL is not safe.
func NewClient(opts ...Option) (*Client, error) {
	var cfg config
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.hasKey && cfg.token != nil {
		return nil, &ConfigError{"give an API key or a token source, not both"}
	}
	var credential func(context.Context) (string, error)
	switch {
	case cfg.token != nil:
		credential = cfg.token
	default:
		key := cfg.apiKey
		if !cfg.hasKey {
			key = os.Getenv("SANDSCALE_API_KEY")
		}
		if strings.TrimSpace(key) == "" {
			return nil, &ConfigError{"no credential: use WithAPIKey or WithTokenSource, or set SANDSCALE_API_KEY"}
		}
		credential = func(context.Context) (string, error) { return key, nil }
	}
	base := cfg.baseURL
	if base == "" {
		base = os.Getenv("SANDSCALE_BASE_URL")
	}
	if base == "" {
		base = DefaultBaseURL
	}
	base, err := checkURL(base, "base URL")
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(base)
	c := &Client{
		baseURL:    base,
		front:      u.Hostname() == frontDoorHost,
		orgID:      cfg.orgID,
		region:     cfg.region,
		credential: credential,
		regionURLs: map[string]string{},
		timeout:    cfg.timeout,
		maxRetries: 2,
		userAgent:  "sandscale-sdk-go/" + Version,
		now:        time.Now,
		sleep: func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		},
	}
	if c.orgID == "" {
		c.orgID = os.Getenv("SANDSCALE_ORG_ID")
	}
	if c.timeout <= 0 {
		c.timeout = 60 * time.Second
	}
	if cfg.retriesSet {
		c.maxRetries = max(0, cfg.maxRetries)
	}
	for name, raw := range cfg.regionURLs {
		v, err := checkURL(raw, "region URL of "+name)
		if err != nil {
			return nil, err
		}
		c.regionURLs[name] = v
	}
	hc := &http.Client{}
	if cfg.hc != nil {
		cp := *cfg.hc
		hc = &cp
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c.hc = hc
	c.Sandboxes = &SandboxesService{c}
	c.Workspaces = &WorkspacesService{c}
	c.Webhooks = &WebhooksService{c}
	c.Snapshots = &SnapshotsService{c}
	c.Templates = &TemplatesService{c}
	c.Policy = &PolicyService{c}
	c.Account = &AccountService{c}
	return c, nil
}

// BaseURL returns the API origin the client was configured with.
func (c *Client) BaseURL() string { return c.baseURL }

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkURL validates an API origin: https, or http only to loopback; no credentials, query or fragment.
func checkURL(raw, what string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return "", &ConfigError{what + " is not an absolute URL"}
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Contains(raw, "?") || strings.Contains(raw, "#") {
		return "", &ConfigError{what + " must not carry credentials, a query or a fragment"}
	}
	if !(u.Scheme == "https" || (u.Scheme == "http" && isLoopback(u.Hostname()))) {
		return "", &ConfigError{what + " must use https (http only to a loopback host)"}
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// CallOption changes one call.
type CallOption func(*callConfig)

type callConfig struct {
	region   string
	fileMode string
	cursor   string
	limit    int
}

func applyCall(opts []CallOption) callConfig {
	var cc callConfig
	for _, o := range opts {
		o(&cc)
	}
	return cc
}

func (c *Client) regionOf(named string) string {
	if named != "" {
		return named
	}
	return c.region
}

func (c *Client) requireOrg() (string, error) {
	if c.orgID == "" {
		return "", &ConfigError{"this call needs an organization: use WithOrgID or set SANDSCALE_ORG_ID"}
	}
	return url.PathEscape(c.orgID), nil
}

func seg(s string) (string, error) {
	if s == "" {
		return "", &ConfigError{"an id is empty"}
	}
	return url.PathEscape(s), nil
}

// segs escapes several path segments; it fails when one is empty.
func segs(parts ...string) ([]string, error) {
	out := make([]string, len(parts))
	for i, p := range parts {
		s, err := seg(p)
		if err != nil {
			return nil, err
		}
		out[i] = s
	}
	return out, nil
}

type regionEntry struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	APIURL string `json:"api_url"`
}

// originFor returns the API origin of a region. Explicit region URLs win. On Sandscale (the front
// door) a region is "us" or "eu" ("us1" names the same); against another base URL (a self-hosted
// Keystone) it is looked up in the server's public region list.
func (c *Client) originFor(ctx context.Context, region string) (string, error) {
	if region == "" {
		return c.baseURL, nil
	}
	if u, ok := c.regionURLs[region]; ok {
		return u, nil
	}
	if c.front {
		if u, ok := regionURLs[sandscaleRegion(region)]; ok {
			return u, nil
		}
		return "", &APIError{Code: "region_unknown", Kind: KindRegion,
			Message: fmt.Sprintf("Sandscale has no region %s; use us or eu", region)}
	}
	entries, err := c.regions(ctx)
	if err != nil {
		return "", err
	}
	var matches []regionEntry
	for _, e := range entries {
		if e.ID == region {
			matches = append(matches, e)
		}
	}
	if len(matches) == 0 {
		re := regexp.MustCompile("^" + regexp.QuoteMeta(region) + `\d+$`)
		for _, e := range entries {
			if re.MatchString(e.ID) {
				matches = append(matches, e)
			}
		}
	}
	switch {
	case len(matches) == 0:
		return "", &APIError{Code: "region_unknown", Kind: KindRegion, Message: "the server lists no region " + region}
	case len(matches) > 1:
		ids := make([]string, len(matches))
		for i, m := range matches {
			ids[i] = m.ID
		}
		return "", &APIError{Code: "region_ambiguous", Kind: KindRegion,
			Message: fmt.Sprintf("region %s matches %s; name one", region, strings.Join(ids, ", "))}
	}
	m := matches[0]
	if m.Status != "live" || m.APIURL == "" {
		return "", &APIError{Code: "region_unavailable", Kind: KindRegion, Region: m.ID,
			Message: fmt.Sprintf("region %s is not available now (%s)", m.ID, m.Status)}
	}
	return checkURL(m.APIURL, "the API URL of region "+m.ID)
}

// liveRegions lists the regions a list call without a region reads.
func (c *Client) liveRegions(ctx context.Context) ([]string, error) {
	if len(c.regionURLs) > 0 {
		names := make([]string, 0, len(c.regionURLs))
		for n := range c.regionURLs {
			names = append(names, n)
		}
		sort.Strings(names)
		return names, nil
	}
	entries, err := c.regions(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		if e.Status != "live" || (!c.front && e.APIURL == "") {
			continue
		}
		name := e.ID
		if c.front {
			name = sandscaleRegion(e.ID)
			if _, ok := regionURLs[name]; !ok {
				continue
			}
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (c *Client) regions(ctx context.Context) ([]regionEntry, error) {
	c.mu.Lock()
	if c.regionList != nil && c.now().Sub(c.regionListAt) < regionListTTL {
		l := c.regionList
		c.mu.Unlock()
		return l, nil
	}
	c.mu.Unlock()
	var body struct {
		Regions []regionEntry `json:"regions"`
	}
	// The region list is public: no credential is sent.
	if err := c.doJSON(ctx, request{method: http.MethodGet, path: "/api/v1/regions", noAuth: true, noOrg: true}, &body); err != nil {
		return nil, err
	}
	var entries []regionEntry
	for _, e := range body.Regions {
		if e.ID != "" {
			entries = append(entries, e)
		}
	}
	c.mu.Lock()
	c.regionList, c.regionListAt = entries, c.now()
	c.mu.Unlock()
	return entries, nil
}

type request struct {
	method  string
	path    string
	query   url.Values
	body    any
	accept  string
	timeout time.Duration // 0: the client default
	region  string
	stream  bool // return the open response; no timeout beyond ctx
	noAuth  bool
	noOrg   bool
}

type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b cancelBody) Close() error { err := b.ReadCloser.Close(); b.cancel(); return err }

func retryableMethod(m string) bool { return m == http.MethodGet || m == http.MethodHead }

// send performs one call, retrying safe calls. On success it returns the open response (stream)
// or the read body.
func (c *Client) send(ctx context.Context, r request) (*http.Response, []byte, error) {
	origin := c.baseURL
	if !r.noAuth || r.region != "" {
		var err error
		if origin, err = c.originFor(ctx, c.regionOf(r.region)); err != nil {
			return nil, nil, err
		}
	}
	u := origin + r.path
	if len(r.query) > 0 {
		u += "?" + r.query.Encode()
	}
	var payload []byte
	if r.body != nil {
		var err error
		if payload, err = json.Marshal(r.body); err != nil {
			return nil, nil, fmt.Errorf("sandscale: encode request: %w", err)
		}
	}
	var auth string
	if !r.noAuth {
		tok, err := c.credential(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("sandscale: token source: %w", err)
		}
		if strings.TrimSpace(tok) == "" {
			return nil, nil, &ConfigError{"the token source returned an empty token"}
		}
		auth = "Bearer " + tok
	}
	retries := 0
	if retryableMethod(r.method) {
		retries = c.maxRetries
	}
	for attempt := 0; ; attempt++ {
		resp, body, err := c.attempt(ctx, r, u, auth, payload)
		if err == nil {
			return resp, body, nil
		}
		var api *APIError
		retry := false
		var ce *ConnectionError
		switch {
		case errors.As(err, &api):
			retry = api.Retryable()
		case errors.As(err, &ce):
			retry = true
		}
		if !retry || attempt >= retries || ctx.Err() != nil {
			return nil, nil, err
		}
		wait := time.Duration(rand.Float64() * float64(min(maxBackoff, 500*time.Millisecond<<attempt)))
		if api != nil && api.RetryAfter > 0 {
			wait = min(api.RetryAfter, maxRetryAfter)
		}
		if err := c.sleep(ctx, wait); err != nil {
			return nil, nil, err
		}
	}
}

func (c *Client) attempt(ctx context.Context, r request, u, auth string, payload []byte) (*http.Response, []byte, error) {
	cctx, cancel := ctx, context.CancelFunc(func() {})
	if !r.stream {
		d := r.timeout
		if d <= 0 {
			d = c.timeout
		}
		cctx, cancel = context.WithTimeout(ctx, d)
	}
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(cctx, r.method, u, rd)
	if err != nil {
		cancel()
		return nil, nil, &ConfigError{"bad request URL: " + err.Error()}
	}
	accept := r.accept
	if accept == "" {
		accept = "application/json"
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", c.userAgent)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if c.orgID != "" && !r.noOrg {
		req.Header.Set("X-Org-ID", c.orgID)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		cancel()
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		reason := "failed"
		if errors.Is(err, context.DeadlineExceeded) {
			reason = "timed out"
		}
		return nil, nil, &ConnectionError{Op: r.method + " " + r.path + " " + reason, Err: unwrapURLError(err)}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		resp.Body.Close()
		cancel()
		return nil, nil, parseError(resp.StatusCode, http.StatusText(resp.StatusCode), body, resp.Header, c.now())
	}
	if r.stream {
		resp.Body = cancelBody{resp.Body, cancel}
		return resp, nil, nil
	}
	defer cancel()
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, &ConnectionError{Op: r.method + " " + r.path + " read", Err: err}
	}
	return resp, body, nil
}

func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// doJSON sends a request and decodes the JSON answer into out (nil: ignore the body).
func (c *Client) doJSON(ctx context.Context, r request, out any) error {
	_, body, err := c.send(ctx, r)
	if err != nil {
		return err
	}
	if out == nil || len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("sandscale: decode answer of %s %s: %w", r.method, r.path, err)
	}
	return nil
}

// attacher is implemented by every resource: it records the region and the server's full answer.
type attacher interface {
	attach(region string, raw json.RawMessage)
}

// getResource decodes one resource and attaches its region and raw answer.
func getResource[T any, P interface {
	*T
	attacher
}](ctx context.Context, c *Client, r request, region string) (*T, error) {
	_, body, err := c.send(ctx, r)
	if err != nil {
		return nil, err
	}
	out := new(T)
	if err := json.Unmarshal(body, out); err != nil {
		return nil, fmt.Errorf("sandscale: decode answer of %s %s: %w", r.method, r.path, err)
	}
	P(out).attach(region, json.RawMessage(body))
	return out, nil
}

// RegionPage describes one region's page of a list. A list without a region reads every live
// region and returns one RegionPage per region.
type RegionPage struct {
	Region     string
	NextCursor string
	HasMore    bool
	// Err is set when this region could not be read; the other regions' items are still returned.
	Err error
}

// listAcrossRegions runs one list call per region (or the named one) and merges the pages. It
// returns an error only when every region failed.
func listAcrossRegions[T any](ctx context.Context, c *Client, named string,
	one func(ctx context.Context, region string) ([]T, RegionPage, error)) ([]T, []RegionPage, error) {
	if region := c.regionOf(named); region != "" {
		items, page, err := one(ctx, region)
		if err != nil {
			return nil, nil, err
		}
		page.Region = region
		return items, []RegionPage{page}, nil
	}
	regions, err := c.liveRegions(ctx)
	if err != nil || len(regions) == 0 {
		regions = []string{""} // a single-region installation
	}
	type result struct {
		items []T
		page  RegionPage
		err   error
	}
	results := make([]result, len(regions))
	var wg sync.WaitGroup
	for i, r := range regions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			items, page, err := one(ctx, r)
			page.Region = r
			results[i] = result{items, page, err}
		}()
	}
	wg.Wait()
	var all []T
	var pages []RegionPage
	failed := 0
	var first error
	for _, r := range results {
		if r.err != nil {
			failed++
			if first == nil {
				first = r.err
			}
			r.page.Err, r.page.HasMore, r.page.NextCursor = r.err, false, ""
			pages = append(pages, r.page)
			continue
		}
		all = append(all, r.items...)
		pages = append(pages, r.page)
	}
	if failed == len(results) {
		return nil, nil, first
	}
	return all, pages, nil
}

// Time is a timestamp that tolerates the empty string and null, which the server sends for a
// moment that has not happened (a sandbox that has not ended). The zero Time means "not set".
type Time struct{ time.Time }

// UnmarshalJSON reads an RFC 3339 timestamp; "" and null leave the zero value.
func (t *Time) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		t.Time = time.Time{}
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return fmt.Errorf("sandscale: bad timestamp %q: %w", s, err)
	}
	t.Time = parsed
	return nil
}

// MarshalJSON writes RFC 3339, or null for the zero Time.
func (t Time) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(t.Time.Format(time.RFC3339Nano))
}
