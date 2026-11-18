// Copyright 2026 Neural Inverse
// SPDX-License-Identifier: Apache-2.0

package sandscale

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// execMargin is the worker margin the server adds to a command's own timeout.
const execMargin = 30 * time.Second

// SandboxesService starts, runs and stops sandboxes.
type SandboxesService struct{ c *Client }

// VaultEnvRef names one Keystone Vault value of a sandbox's environment: variable Name gets Field
// of the secret at Path. The server reads it as the caller and hands it to the sandbox only; the
// value never passes through the SDK.
type VaultEnvRef struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Field string `json:"field"`
}

// CreateSandboxParams are the members of a sandbox start. Zero members are not sent.
type CreateSandboxParams struct {
	// Template is a template id of the organization, or a built-in ("builtin:base", "builtin:python").
	Template string `json:"template_id,omitempty"`
	// SnapshotID starts from a snapshot instead.
	SnapshotID string `json:"snapshot_id,omitempty"`
	// CPUCount, MemMB and DiskMB size the sandbox; with a template, nonzero values must match it.
	CPUCount int `json:"cpu_count,omitempty"`
	MemMB    int `json:"mem_mb,omitempty"`
	DiskMB   int `json:"disk_mb,omitempty"`
	// TTLSeconds is the time until the sandbox stops (server default 3600, at most 86400).
	TTLSeconds int `json:"ttl_seconds,omitempty"`
	// Network is "none" (default) or "allowlist".
	Network string `json:"network,omitempty"`
	// Image is an OCI image pinned by digest (name@sha256:...).
	Image string `json:"image,omitempty"`
	// Runtime places the sandbox on a runtime ("firecracker" for Sandscale organizations).
	Runtime       string            `json:"runtime,omitempty"`
	EnvironmentID string            `json:"environment_id,omitempty"`
	Env           map[string]string `json:"env,omitempty"`
	VaultEnv      []VaultEnvRef     `json:"vault_env,omitempty"`
	Command       []string          `json:"command,omitempty"`
	Name          string            `json:"name,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	// Metadata["project_id"] runs the sandbox in a project.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Suspend says whether pause and resume are possible now, as the server says.
type Suspend struct {
	CanPause  bool   `json:"can_pause"`
	CanResume bool   `json:"can_resume"`
	Reason    string `json:"reason,omitempty"`
}

// Sandbox is one sandbox.
type Sandbox struct {
	ID           string            `json:"id"`
	Status       string            `json:"status"`
	Name         string            `json:"name,omitempty"`
	TemplateID   string            `json:"template_id,omitempty"`
	CPUCount     int               `json:"cpu_count,omitempty"`
	MemMB        int               `json:"mem_mb,omitempty"`
	TTLSeconds   int               `json:"ttl_seconds,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	StatusReason string            `json:"status_reason,omitempty"`
	CreatedAt    Time              `json:"created_at"`
	StartedAt    Time              `json:"started_at"`
	TerminatedAt Time              `json:"terminated_at"`
	Suspend      *Suspend          `json:"suspend,omitempty"`

	// Region is the region the sandbox lives in; pass it to later calls with WithRegion.
	Region string `json:"-"`
	// Raw is the server's full answer.
	Raw json.RawMessage `json:"-"`
}

func (s *Sandbox) attach(region string, raw json.RawMessage) { s.Region, s.Raw = region, raw }

// Create starts a sandbox. Limits, entitlement and policy are decided by the server.
func (s *SandboxesService) Create(ctx context.Context, p CreateSandboxParams, opts ...CallOption) (*Sandbox, error) {
	region := s.c.regionOf(applyCall(opts).region)
	return getResource[Sandbox](ctx, s.c, request{method: http.MethodPost, path: "/api/v1/sandbox/instances", body: p, region: region}, region)
}

// Get returns one sandbox.
func (s *SandboxesService) Get(ctx context.Context, id string, opts ...CallOption) (*Sandbox, error) {
	e, err := seg(id)
	if err != nil {
		return nil, err
	}
	region := s.c.regionOf(applyCall(opts).region)
	return getResource[Sandbox](ctx, s.c, request{method: http.MethodGet, path: "/api/v1/sandbox/instances/" + e, region: region}, region)
}

// SandboxList is a list of sandboxes, with one RegionPage per region read.
type SandboxList struct {
	Data  []Sandbox
	Pages []RegionPage
}

// ListSandboxesParams filters a sandbox list.
type ListSandboxesParams struct {
	Status    string
	ProjectID string
	Limit     int
	// Cursor is a cursor of one region's page; it needs WithRegion.
	Cursor string
}

// List lists sandboxes: of one region when WithRegion (or the client's default region) names one,
// else of every live region. A region that cannot be read is reported in its RegionPage.Err
// while the others' sandboxes are still returned.
func (s *SandboxesService) List(ctx context.Context, p ListSandboxesParams, opts ...CallOption) (*SandboxList, error) {
	q := url.Values{}
	if p.Status != "" {
		q.Set("status", p.Status)
	}
	if p.ProjectID != "" {
		q.Set("project_id", p.ProjectID)
	}
	if p.Limit > 0 {
		q.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.Cursor != "" {
		q.Set("cursor", p.Cursor)
	}
	items, pages, err := listAcrossRegions(ctx, s.c, applyCall(opts).region, func(ctx context.Context, region string) ([]Sandbox, RegionPage, error) {
		var raw struct {
			Data       []json.RawMessage `json:"data"`
			NextCursor *string           `json:"next_cursor"`
			HasMore    bool              `json:"has_more"`
		}
		if err := s.c.doJSON(ctx, request{method: http.MethodGet, path: "/api/v1/sandbox/instances", query: q, region: region}, &raw); err != nil {
			return nil, RegionPage{}, err
		}
		out, err := decodeAll[Sandbox](raw.Data, region)
		page := RegionPage{HasMore: raw.HasMore}
		if raw.NextCursor != nil {
			page.NextCursor = *raw.NextCursor
		}
		return out, page, err
	})
	if err != nil {
		return nil, err
	}
	return &SandboxList{Data: items, Pages: pages}, nil
}

// decodeAll decodes a list of resources, attaching region and raw to each.
func decodeAll[T any, P interface {
	*T
	attacher
}](raws []json.RawMessage, region string) ([]T, error) {
	out := make([]T, 0, len(raws))
	for _, r := range raws {
		var v T
		if err := json.Unmarshal(r, &v); err != nil {
			return nil, err
		}
		P(&v).attach(region, r)
		out = append(out, v)
	}
	return out, nil
}

// Stop stops the sandbox and releases it.
func (s *SandboxesService) Stop(ctx context.Context, id string, opts ...CallOption) error {
	e, err := seg(id)
	if err != nil {
		return err
	}
	return s.c.doJSON(ctx, request{method: http.MethodDelete, path: "/api/v1/sandbox/instances/" + e, region: applyCall(opts).region}, nil)
}

// PauseResult is the answer of Pause and Resume.
type PauseResult struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// Pause pauses a microVM sandbox (a container sandbox answers 409 pause_unsupported).
func (s *SandboxesService) Pause(ctx context.Context, id string, opts ...CallOption) (*PauseResult, error) {
	return s.lifecycle(ctx, id, "pause", opts)
}

// Resume resumes a paused sandbox.
func (s *SandboxesService) Resume(ctx context.Context, id string, opts ...CallOption) (*PauseResult, error) {
	return s.lifecycle(ctx, id, "resume", opts)
}

func (s *SandboxesService) lifecycle(ctx context.Context, id, verb string, opts []CallOption) (*PauseResult, error) {
	e, err := seg(id)
	if err != nil {
		return nil, err
	}
	var out PauseResult
	err = s.c.doJSON(ctx, request{method: http.MethodPost, path: "/api/v1/sandbox/instances/" + e + "/" + verb, region: applyCall(opts).region}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// KeepAwakeResult is the answer of KeepAwake.
type KeepAwakeResult struct {
	ID         string `json:"id"`
	KeepAwake  bool   `json:"keep_awake"`
	Until      Time   `json:"until"`
	Reason     string `json:"reason,omitempty"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// KeepAwakeParams say how long a sandbox stays awake.
type KeepAwakeParams struct {
	// TTLSeconds is how long the sandbox stays awake (0 clears it; at most 86400).
	TTLSeconds int
	// Reason is shown to people who ask why the sandbox is not hibernated (at most 100 characters).
	Reason string
}

// KeepAwake keeps the sandbox from hibernating between calls, with a reason people can read
// back. A 503 sandbox_waking (the sandbox is resuming) is retried a few times after the server's
// Retry-After before it is returned.
func (s *SandboxesService) KeepAwake(ctx context.Context, id string, p KeepAwakeParams, opts ...CallOption) (*KeepAwakeResult, error) {
	e, err := seg(id)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"ttl_seconds": p.TTLSeconds}
	if p.Reason != "" {
		body["reason"] = p.Reason
	}
	for attempt := 0; ; attempt++ {
		var out KeepAwakeResult
		err := s.c.doJSON(ctx, request{method: http.MethodPost, path: "/api/v1/sandbox/instances/" + e + "/keep-awake", body: body, region: applyCall(opts).region}, &out)
		if err == nil {
			return &out, nil
		}
		if !errors.Is(err, ErrSandboxWaking) || attempt >= 3 {
			return nil, err
		}
		api, _ := AsAPIError(err)
		wait := min(api.RetryAfter, 10*time.Second)
		if wait <= 0 {
			wait = 500 * time.Millisecond << attempt
		}
		if err := s.c.sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// Snapshot is a snapshot of a sandbox's /workspace.
type Snapshot struct {
	ID         string `json:"id"`
	InstanceID string `json:"instance_id"`
	// Status is "creating", "ready" or "failed".
	Status    string `json:"status"`
	Label     string `json:"label"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256,omitempty"`
	CreatedAt Time   `json:"created_at"`
	ExpiresAt Time   `json:"expires_at"`
	Failure   string `json:"failure,omitempty"`

	Region string          `json:"-"`
	Raw    json.RawMessage `json:"-"`
}

func (s *Snapshot) attach(region string, raw json.RawMessage) { s.Region, s.Raw = region, raw }

// SnapshotParams describe a snapshot to take.
type SnapshotParams struct {
	// Label is a name people can read back; it may be empty.
	Label string
}

// Snapshot snapshots the sandbox's /workspace. Start a new sandbox from it with
// CreateSandboxParams.SnapshotID.
func (s *SandboxesService) Snapshot(ctx context.Context, id string, p SnapshotParams, opts ...CallOption) (*Snapshot, error) {
	e, err := seg(id)
	if err != nil {
		return nil, err
	}
	var body any
	if p.Label != "" {
		body = map[string]string{"label": p.Label}
	}
	region := s.c.regionOf(applyCall(opts).region)
	return getResource[Snapshot](ctx, s.c, request{method: http.MethodPost, path: "/api/v1/sandbox/instances/" + e + "/snapshot", body: body, region: region}, region)
}

// ListSnapshots lists the snapshots of one sandbox.
func (s *SandboxesService) ListSnapshots(ctx context.Context, id string, opts ...CallOption) ([]Snapshot, error) {
	e, err := seg(id)
	if err != nil {
		return nil, err
	}
	region := s.c.regionOf(applyCall(opts).region)
	var raw struct {
		Snapshots []json.RawMessage `json:"snapshots"`
	}
	if err := s.c.doJSON(ctx, request{method: http.MethodGet, path: "/api/v1/sandbox/instances/" + e + "/snapshots", region: region}, &raw); err != nil {
		return nil, err
	}
	return decodeAll[Snapshot](raw.Snapshots, region)
}

// ExecParams describe a command to run in a sandbox.
type ExecParams struct {
	// Command is the argv to run. Use Shell for a shell command line.
	Command []string
	// Shell, when Command is empty, runs `sh -c Shell`.
	Shell string
	Env   map[string]string
	// Workdir is /workspace (default) or a directory below it.
	Workdir string
	// Timeout is how long the command may run (default 60s).
	Timeout time.Duration
	// Stdin is piped to standard input.
	Stdin []byte
	// OnStdout and OnStderr receive live output, in order, as the server releases it. When either
	// is set the command is started without waiting and its output is streamed.
	OnStdout func(data string)
	OnStderr func(data string)
}

// ExecResult is how a command ended.
type ExecResult struct {
	RunID     string
	ExitCode  int
	Stdout    string
	Stderr    string
	Duration  time.Duration
	OOMKilled bool
	TimedOut  bool
	// Streamed is true when the output callbacks received live output; false when they got the
	// final output at the end.
	Streamed bool
}

type execAnswer struct {
	RunID      string `json:"run_id"`
	ID         string `json:"id"`
	ExitCode   *int   `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMs int64  `json:"duration_ms"`
	OOMKilled  bool   `json:"oom_killed"`
	TimedOut   bool   `json:"timed_out"`
	Status     string `json:"status"`
}

func (a execAnswer) result(stdout, stderr string, streamed bool) *ExecResult {
	id := a.RunID
	if id == "" {
		id = a.ID
	}
	code := -1
	if a.ExitCode != nil {
		code = *a.ExitCode
	}
	return &ExecResult{
		RunID: id, ExitCode: code, Stdout: stdout, Stderr: stderr,
		Duration:  time.Duration(a.DurationMs) * time.Millisecond,
		OOMKilled: a.OOMKilled || a.Status == "oom_killed",
		TimedOut:  a.TimedOut || a.Status == "timed_out",
		Streamed:  streamed,
	}
}

// Exec runs a command and returns its exit code and output. A non-zero exit code is a result,
// not an error. With OnStdout or OnStderr the output is delivered live; a server that answers
// with the finished result instead gets the callbacks the final output once (Streamed false).
func (s *SandboxesService) Exec(ctx context.Context, id string, p ExecParams, opts ...CallOption) (*ExecResult, error) {
	e, err := seg(id)
	if err != nil {
		return nil, err
	}
	argv := p.Command
	if len(argv) == 0 {
		if p.Shell == "" {
			return nil, &ConfigError{"Exec needs Command or Shell"}
		}
		argv = []string{"sh", "-c", p.Shell}
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	body := map[string]any{"command": argv, "timeout_sec": int(timeout.Round(time.Second) / time.Second)}
	if p.Env != nil {
		body["env"] = p.Env
	}
	if p.Workdir != "" {
		body["workdir"] = p.Workdir
	}
	if p.Stdin != nil {
		body["stdin"] = p.Stdin // base64 on the wire
	}
	live := p.OnStdout != nil || p.OnStderr != nil
	if live {
		body["wait"] = false
	}
	region := s.c.regionOf(applyCall(opts).region)
	var ans execAnswer
	err = s.c.doJSON(ctx, request{
		method: http.MethodPost, path: "/api/v1/sandbox/instances/" + e + "/exec", body: body,
		timeout: timeout + execMargin, region: region,
	}, &ans)
	if err != nil {
		return nil, err
	}
	if !live || ans.ExitCode != nil {
		res := ans.result(ans.Stdout, ans.Stderr, false)
		if live {
			if res.Stdout != "" && p.OnStdout != nil {
				p.OnStdout(res.Stdout)
			}
			if res.Stderr != "" && p.OnStderr != nil {
				p.OnStderr(res.Stderr)
			}
		}
		return res, nil
	}
	// The run is queued: its output and end come from its log stream.
	var stdout, stderr strings.Builder
	end, err := s.StreamLogs(ctx, id, ans.RunID, func(c OutputChunk) error {
		if c.Stream == "stderr" {
			stderr.WriteString(c.Data)
			if p.OnStderr != nil {
				p.OnStderr(c.Data)
			}
		} else {
			stdout.WriteString(c.Data)
			if p.OnStdout != nil {
				p.OnStdout(c.Data)
			}
		}
		return nil
	}, append(opts, func(c *callConfig) { c.region = region })...)
	if err != nil {
		return nil, err
	}
	final := execAnswer{RunID: ans.RunID, ExitCode: end.ExitCode, OOMKilled: end.OOMKilled, TimedOut: end.TimedOut, Status: end.Status, DurationMs: end.DurationMs}
	if end.ExitCode == nil {
		// A server whose stream end carries no result: read the run.
		runPath, err := seg(ans.RunID)
		if err != nil {
			return nil, err
		}
		if err := s.c.doJSON(ctx, request{method: http.MethodGet, path: "/api/v1/sandbox/runs/" + runPath, region: region}, &final); err != nil {
			return nil, err
		}
		final.RunID = ans.RunID
	}
	return final.result(stdout.String(), stderr.String(), true), nil
}

// OutputChunk is one piece of a run's output.
type OutputChunk struct {
	// Stream is "stdout" or "stderr".
	Stream     string
	Data       string
	ChunkIndex int
}

// RunEnd is how a run ended, as its log stream's done event says. ExitCode is nil when the
// stream's end did not carry it.
type RunEnd struct {
	RunID      string
	Status     string
	ExitCode   *int
	DurationMs int64
	OOMKilled  bool
	TimedOut   bool
}

// StreamLogs streams a run's output (Server-Sent Events) to fn, resuming after a dropped
// connection, until the run ends or fn returns an error (which is returned). It returns how the
// run ended.
func (s *SandboxesService) StreamLogs(ctx context.Context, id, runID string, fn func(OutputChunk) error, opts ...CallOption) (*RunEnd, error) {
	e, err := seg(id)
	if err != nil {
		return nil, err
	}
	if _, err := seg(runID); err != nil {
		return nil, err
	}
	region := applyCall(opts).region
	next := -1
	reconnects := 0
	for {
		q := url.Values{"run_id": {runID}}
		if next >= 0 {
			q.Set("from_chunk", strconv.Itoa(next))
		}
		resp, _, err := s.c.send(ctx, request{
			method: http.MethodGet, path: "/api/v1/sandbox/instances/" + e + "/logs", query: q,
			accept: "text/event-stream", stream: true, region: region,
		})
		if err != nil {
			return nil, err
		}
		before := next
		end, done, err := readLogEvents(resp.Body, runID, &next, fn)
		resp.Body.Close()
		if next != before {
			reconnects = 0 // the connection made progress: a long run may reconnect as often as it must
		}
		if err != nil {
			var cb callbackError
			if errors.As(err, &cb) {
				return nil, cb.err
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			var api *APIError
			if errors.As(err, &api) || reconnects >= 3 {
				return nil, err
			}
		}
		if done {
			return end, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if reconnects >= 3 {
			return nil, &ConnectionError{Op: "stream logs of run " + runID, Err: io.ErrUnexpectedEOF}
		}
		reconnects++
	}
}

type callbackError struct{ err error }

func (e callbackError) Error() string { return e.err.Error() }

// readLogEvents reads one SSE connection. done is true after the "done" event.
func readLogEvents(body io.Reader, runID string, next *int, fn func(OutputChunk) error) (*RunEnd, bool, error) {
	br := bufio.NewReaderSize(body, 64<<10)
	event, data := "message", []string{}
	dispatch := func() (*RunEnd, bool, error) {
		defer func() { event, data = "message", data[:0] }()
		if len(data) == 0 {
			return nil, false, nil
		}
		payload := strings.Join(data, "\n")
		switch event {
		case "done":
			var d struct {
				RunID      string `json:"run_id"`
				Status     string `json:"status"`
				ExitCode   *int   `json:"exit_code"`
				DurationMs int64  `json:"duration_ms"`
				OOMKilled  bool   `json:"oom_killed"`
				TimedOut   bool   `json:"timed_out"`
			}
			_ = json.Unmarshal([]byte(payload), &d)
			if d.RunID == "" {
				d.RunID = runID
			}
			return &RunEnd{RunID: d.RunID, Status: d.Status, ExitCode: d.ExitCode, DurationMs: d.DurationMs, OOMKilled: d.OOMKilled, TimedOut: d.TimedOut}, true, nil
		case "error":
			// The server withheld the rest (its DLP scan failed): never a silently cut output.
			var d struct{ Code, Message string }
			_ = json.Unmarshal([]byte(payload), &d)
			if d.Code == "" {
				d.Code = "stream_error"
			}
			if d.Message == "" {
				d.Message = "the output stream ended with an error"
			}
			return nil, false, &APIError{Status: 503, Code: d.Code, Message: d.Message, Kind: KindServiceUnavailable}
		case "chunk":
			var d struct {
				Stream     string  `json:"stream"`
				Data       *string `json:"data"`
				ChunkIndex int     `json:"chunk_index"`
			}
			if json.Unmarshal([]byte(payload), &d) != nil || d.Data == nil {
				return nil, false, nil
			}
			*next = d.ChunkIndex + 1
			stream := "stdout"
			if d.Stream == "stderr" {
				stream = "stderr"
			}
			if err := fn(OutputChunk{Stream: stream, Data: *d.Data, ChunkIndex: d.ChunkIndex}); err != nil {
				return nil, false, callbackError{err}
			}
		}
		return nil, false, nil
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil && line == "" {
			// The connection ended: flush a pending event, then report how it ended.
			if end, done, derr := dispatch(); derr != nil || done {
				return end, done, derr
			}
			if err == io.EOF {
				return nil, false, nil
			}
			return nil, false, err
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case line == "":
			if end, done, derr := dispatch(); derr != nil || done {
				return end, done, derr
			}
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(line[len("event:"):])
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(line[len("data:"):], " "))
		}
	}
}

// WriteFile writes a file into the sandbox (at most what the server accepts per request).
// WithFileMode sets its permission bits.
func (s *SandboxesService) WriteFile(ctx context.Context, id, path string, data []byte, opts ...CallOption) error {
	e, err := seg(id)
	if err != nil {
		return err
	}
	cc := applyCall(opts)
	if data == nil {
		data = []byte{} // an empty file, not null
	}
	body := map[string]any{"path": path, "content": data}
	if cc.fileMode != "" {
		body["mode"] = cc.fileMode
	}
	return s.c.doJSON(ctx, request{method: http.MethodPut, path: "/api/v1/sandbox/instances/" + e + "/files", body: body, region: cc.region}, nil)
}

// WithFileMode sets the permission bits of WriteFile (for example "0755").
func WithFileMode(mode string) CallOption { return func(c *callConfig) { c.fileMode = mode } }

type filesAnswer struct {
	Type    string `json:"type"`
	Content []byte `json:"content"`
	Entries []struct {
		Name string `json:"name"`
		Type string `json:"type"`
		Size *int64 `json:"size_bytes"`
	} `json:"entries"`
}

func (s *SandboxesService) files(ctx context.Context, id, path string, opts []CallOption) (*filesAnswer, error) {
	e, err := seg(id)
	if err != nil {
		return nil, err
	}
	var a filesAnswer
	err = s.c.doJSON(ctx, request{method: http.MethodGet, path: "/api/v1/sandbox/instances/" + e + "/files", query: url.Values{"path": {path}}, region: applyCall(opts).region}, &a)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// ReadFile reads a regular file from the sandbox.
func (s *SandboxesService) ReadFile(ctx context.Context, id, path string, opts ...CallOption) ([]byte, error) {
	a, err := s.files(ctx, id, path, opts)
	if err != nil {
		return nil, err
	}
	if a.Type != "file" {
		return nil, &APIError{Status: 400, Code: "not_a_file", Message: path + " is not a regular file", Kind: KindInvalidRequest}
	}
	return a.Content, nil
}

// FileEntry is one entry of a directory listing.
type FileEntry struct {
	Path  string
	Name  string
	IsDir bool
	// Size is the size in bytes, or -1 when the server did not say.
	Size int64
}

// ListFiles lists a directory of the sandbox.
func (s *SandboxesService) ListFiles(ctx context.Context, id, path string, opts ...CallOption) ([]FileEntry, error) {
	a, err := s.files(ctx, id, path, opts)
	if err != nil {
		return nil, err
	}
	if a.Type != "dir" {
		return nil, &APIError{Status: 400, Code: "not_a_directory", Message: path + " is not a directory", Kind: KindInvalidRequest}
	}
	dir := path
	if !strings.HasSuffix(dir, "/") {
		dir += "/"
	}
	out := make([]FileEntry, 0, len(a.Entries))
	for _, en := range a.Entries {
		size := int64(-1)
		if en.Size != nil {
			size = *en.Size
		}
		out = append(out, FileEntry{Path: dir + en.Name, Name: en.Name, IsDir: en.Type == "dir", Size: size})
	}
	return out, nil
}
