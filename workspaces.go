// Copyright 2026 Neural Inverse
// SPDX-License-Identifier: Apache-2.0

package sandscale

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
)

// WorkspacesService manages cloud workspaces. Every call needs an organization id (WithOrgID).
type WorkspacesService struct{ c *Client }

// Workspace is one workspace.
type Workspace struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Health     string `json:"health,omitempty"`
	TemplateID string `json:"template_id,omitempty"`
	OwnerID    string `json:"owner_id,omitempty"`
	ProjectID  string `json:"project_id,omitempty"`
	CreatedAt  Time   `json:"created_at"`
	UpdatedAt  Time   `json:"updated_at"`
	LastUsedAt Time   `json:"last_used_at"`

	Region string          `json:"-"`
	Raw    json.RawMessage `json:"-"`
}

func (w *Workspace) attach(region string, raw json.RawMessage) { w.Region, w.Raw = region, raw }

// WorkspaceBuild is a workspace build: start, stop and rebuild are builds the server queues.
type WorkspaceBuild struct {
	ID             string `json:"id"`
	WorkspaceID    string `json:"workspace_id"`
	State          string `json:"state"`
	DesiredState   string `json:"desired_state,omitempty"`
	BuildNumber    int    `json:"build_number,omitempty"`
	Reason         string `json:"reason,omitempty"`
	FailureMessage string `json:"failure_message,omitempty"`
	CreatedAt      Time   `json:"created_at"`
	CompletedAt    Time   `json:"completed_at"`

	Region string          `json:"-"`
	Raw    json.RawMessage `json:"-"`
}

func (b *WorkspaceBuild) attach(region string, raw json.RawMessage) { b.Region, b.Raw = region, raw }

// ConnectLink is an editor link of ConnectInfo.
type ConnectLink struct {
	IDE      string   `json:"ide"`
	Kind     string   `json:"kind"`
	URL      string   `json:"url"`
	Requires []string `json:"requires,omitempty"`
}

// ConnectInfo says how to connect to a workspace: SSH host and command, port forwarding and editor
// links, as the server allows.
type ConnectInfo struct {
	SSHHost              string        `json:"ssh_host"`
	SSHCommand           string        `json:"ssh_command,omitempty"`
	PortForwardCommand   string        `json:"port_forward_command,omitempty"`
	Folder               string        `json:"folder,omitempty"`
	SSHReady             bool          `json:"ssh_ready"`
	SSHUnavailableReason string        `json:"ssh_unavailable_reason,omitempty"`
	SSHNote              string        `json:"ssh_note,omitempty"`
	Links                []ConnectLink `json:"links,omitempty"`

	Raw json.RawMessage `json:"-"`
}

func (i *ConnectInfo) attach(_ string, raw json.RawMessage) { i.Raw = raw }

// OpenLink is the link that opens a workspace in an IDE, built by the server.
type OpenLink struct {
	IDE string `json:"ide"`
	// Kind is "deeplink" or "url".
	Kind    string `json:"kind"`
	URL     string `json:"url"`
	SSHHost string `json:"ssh_host,omitempty"`
	Folder  string `json:"folder,omitempty"`
	// Requires is what the IDE side needs (for example "config-ssh").
	Requires []string `json:"requires,omitempty"`

	Raw json.RawMessage `json:"-"`
}

func (l *OpenLink) attach(_ string, raw json.RawMessage) { l.Raw = raw }

// CreateWorkspaceParams create a workspace from a template and queue its first build. The plan,
// quota and policy are the server's to decide.
type CreateWorkspaceParams struct {
	Name              string            `json:"name"`
	TemplateID        string            `json:"template_id,omitempty"`
	TemplateVersionID string            `json:"template_version_id,omitempty"`
	Parameters        map[string]string `json:"parameters,omitempty"`
	TTLSeconds        int               `json:"ttl_seconds,omitempty"`
	IdleTimeoutSecs   int               `json:"idle_timeout_seconds,omitempty"`
	// AutostartSchedule is a 5-field cron schedule.
	AutostartSchedule string `json:"autostart_schedule,omitempty"`
	ProjectID         string `json:"project_id,omitempty"`
	EnvironmentID     string `json:"environment_id,omitempty"`
	// Repository is the git repository the workspace is for.
	Repository string `json:"repository,omitempty"`
}

// UpdateWorkspaceParams change the members that are set; nil members are left alone.
type UpdateWorkspaceParams struct {
	Name              *string `json:"name,omitempty"`
	TTLSeconds        *int    `json:"ttl_seconds,omitempty"`
	IdleTimeoutSecs   *int    `json:"idle_timeout_seconds,omitempty"`
	AutostartSchedule *string `json:"autostart_schedule,omitempty"`
}

// RebuildWorkspaceParams queue a rebuild, optionally on another template version.
type RebuildWorkspaceParams struct {
	TemplateVersionID string            `json:"template_version_id,omitempty"`
	Parameters        map[string]string `json:"parameters,omitempty"`
}

// ListWorkspacesParams filter a workspace list.
type ListWorkspacesParams struct {
	Limit  int
	Cursor string
	// All includes deleted workspaces.
	All bool
}

// WorkspaceList is a list of workspaces, with one RegionPage per region read.
type WorkspaceList struct {
	Data  []Workspace
	Pages []RegionPage
}

func (w *WorkspacesService) path(rest ...string) (string, error) {
	org, err := w.c.requireOrg()
	if err != nil {
		return "", err
	}
	p := "/api/v1/orgs/" + org + "/workspaces"
	for _, r := range rest {
		e, err := seg(r)
		if err != nil {
			return "", err
		}
		p += "/" + e
	}
	return p, nil
}

// List lists workspaces: of one region when one is named, else of every live region.
func (w *WorkspacesService) List(ctx context.Context, p ListWorkspacesParams, opts ...CallOption) (*WorkspaceList, error) {
	path, err := w.path()
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	if p.Limit > 0 {
		q.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.Cursor != "" {
		q.Set("cursor", p.Cursor)
	}
	if p.All {
		q.Set("all", "true")
	}
	items, pages, err := listAcrossRegions(ctx, w.c, applyCall(opts).region, func(ctx context.Context, region string) ([]Workspace, RegionPage, error) {
		var raw struct {
			Workspaces []json.RawMessage `json:"workspaces"`
			NextCursor string            `json:"next_cursor"`
		}
		if err := w.c.doJSON(ctx, request{method: http.MethodGet, path: path, query: q, region: region}, &raw); err != nil {
			return nil, RegionPage{}, err
		}
		out, err := decodeAll[Workspace](raw.Workspaces, region)
		return out, RegionPage{NextCursor: raw.NextCursor, HasMore: raw.NextCursor != ""}, err
	})
	if err != nil {
		return nil, err
	}
	return &WorkspaceList{Data: items, Pages: pages}, nil
}

// Get returns one workspace.
func (w *WorkspacesService) Get(ctx context.Context, id string, opts ...CallOption) (*Workspace, error) {
	path, err := w.path(id)
	if err != nil {
		return nil, err
	}
	region := w.c.regionOf(applyCall(opts).region)
	return getResource[Workspace](ctx, w.c, request{method: http.MethodGet, path: path, region: region}, region)
}

// Start queues a start build.
func (w *WorkspacesService) Start(ctx context.Context, id string, opts ...CallOption) (*WorkspaceBuild, error) {
	return w.build(ctx, id, "start", nil, opts)
}

// Stop queues a stop build.
func (w *WorkspacesService) Stop(ctx context.Context, id string, opts ...CallOption) (*WorkspaceBuild, error) {
	return w.build(ctx, id, "stop", nil, opts)
}

// Rebuild queues a rebuild, optionally on another template version.
func (w *WorkspacesService) Rebuild(ctx context.Context, id string, p RebuildWorkspaceParams, opts ...CallOption) (*WorkspaceBuild, error) {
	return w.build(ctx, id, "rebuild", p, opts)
}

func (w *WorkspacesService) build(ctx context.Context, id, verb string, body any, opts []CallOption) (*WorkspaceBuild, error) {
	path, err := w.path(id, verb)
	if err != nil {
		return nil, err
	}
	region := w.c.regionOf(applyCall(opts).region)
	return getResource[WorkspaceBuild](ctx, w.c, request{method: http.MethodPost, path: path, body: body, region: region}, region)
}

// WorkspaceCreated is the answer of Create: the workspace and its queued first build.
type WorkspaceCreated struct {
	Workspace Workspace
	Build     WorkspaceBuild
}

// Create creates a workspace and queues its first build.
func (w *WorkspacesService) Create(ctx context.Context, p CreateWorkspaceParams, opts ...CallOption) (*WorkspaceCreated, error) {
	path, err := w.path()
	if err != nil {
		return nil, err
	}
	region := w.c.regionOf(applyCall(opts).region)
	var raw struct {
		Workspace json.RawMessage `json:"workspace"`
		Build     json.RawMessage `json:"build"`
	}
	if err := w.c.doJSON(ctx, request{method: http.MethodPost, path: path, body: p, region: region}, &raw); err != nil {
		return nil, err
	}
	out := &WorkspaceCreated{}
	if len(raw.Workspace) > 0 {
		if err := json.Unmarshal(raw.Workspace, &out.Workspace); err != nil {
			return nil, err
		}
	}
	if len(raw.Build) > 0 {
		if err := json.Unmarshal(raw.Build, &out.Build); err != nil {
			return nil, err
		}
	}
	out.Workspace.attach(region, raw.Workspace)
	out.Build.attach(region, raw.Build)
	return out, nil
}

// Update changes the members you set.
func (w *WorkspacesService) Update(ctx context.Context, id string, p UpdateWorkspaceParams, opts ...CallOption) (*Workspace, error) {
	path, err := w.path(id)
	if err != nil {
		return nil, err
	}
	region := w.c.regionOf(applyCall(opts).region)
	return getResource[Workspace](ctx, w.c, request{method: http.MethodPatch, path: path, body: p, region: region}, region)
}

// Delete deletes the workspace.
func (w *WorkspacesService) Delete(ctx context.Context, id string, opts ...CallOption) error {
	path, err := w.path(id)
	if err != nil {
		return err
	}
	return w.c.doJSON(ctx, request{method: http.MethodDelete, path: path, region: applyCall(opts).region}, nil)
}

// ConnectInfo says how to connect to the workspace.
func (w *WorkspacesService) ConnectInfo(ctx context.Context, id string, opts ...CallOption) (*ConnectInfo, error) {
	path, err := w.path(id, "connect")
	if err != nil {
		return nil, err
	}
	region := w.c.regionOf(applyCall(opts).region)
	return getResource[ConnectInfo](ctx, w.c, request{method: http.MethodGet, path: path, region: region}, region)
}

// OpenLink returns the link that opens the workspace in ide ("vscode", "cursor", ...), built by
// the server and only for the IDEs the policy allows.
func (w *WorkspacesService) OpenLink(ctx context.Context, id, ide string, opts ...CallOption) (*OpenLink, error) {
	path, err := w.path(id, "open")
	if err != nil {
		return nil, err
	}
	region := w.c.regionOf(applyCall(opts).region)
	l, err := getResource[OpenLink](ctx, w.c, request{method: http.MethodGet, path: path, query: url.Values{"ide": {ide}}, region: region}, region)
	if err != nil {
		return nil, err
	}
	if l.IDE == "" {
		l.IDE = ide
	}
	return l, nil
}
