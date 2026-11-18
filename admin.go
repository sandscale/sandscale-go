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

// SnapshotsService manages the organization's sandbox snapshots (take one with
// SandboxesService.Snapshot).
type SnapshotsService struct{ c *Client }

// SnapshotUsage is the snapshot quota used.
type SnapshotUsage struct {
	Count int   `json:"count"`
	Bytes int64 `json:"bytes"`
}

// SnapshotList is a list of snapshots with the snapshot quota used (summed over the regions read).
type SnapshotList struct {
	Data  []Snapshot
	Pages []RegionPage
	Usage SnapshotUsage
}

// ListSnapshotsParams filter a snapshot list.
type ListSnapshotsParams struct {
	// Limit 0 uses the server default.
	Limit int
}

// List lists the snapshots you may see.
func (s *SnapshotsService) List(ctx context.Context, p ListSnapshotsParams, opts ...CallOption) (*SnapshotList, error) {
	q := url.Values{}
	if p.Limit > 0 {
		q.Set("limit", strconv.Itoa(p.Limit))
	}
	var usage SnapshotUsage
	items, pages, err := listAcrossRegionsLocked(ctx, s.c, applyCall(opts).region, &usage, func(ctx context.Context, region string) ([]Snapshot, RegionPage, SnapshotUsage, error) {
		var raw struct {
			Snapshots []json.RawMessage `json:"snapshots"`
			Usage     SnapshotUsage     `json:"usage"`
		}
		if err := s.c.doJSON(ctx, request{method: http.MethodGet, path: "/api/v1/sandbox/snapshots", query: q, region: region}, &raw); err != nil {
			return nil, RegionPage{}, SnapshotUsage{}, err
		}
		out, err := decodeAll[Snapshot](raw.Snapshots, region)
		return out, RegionPage{}, raw.Usage, err
	})
	if err != nil {
		return nil, err
	}
	return &SnapshotList{Data: items, Pages: pages, Usage: usage}, nil
}

// listAcrossRegionsLocked is listAcrossRegions for a call whose answer also carries a usage to sum.
func listAcrossRegionsLocked[T any](ctx context.Context, c *Client, named string, sum *SnapshotUsage,
	one func(ctx context.Context, region string) ([]T, RegionPage, SnapshotUsage, error)) ([]T, []RegionPage, error) {
	usages := make(chan SnapshotUsage, 16)
	done := make(chan struct{})
	go func() {
		for u := range usages {
			sum.Count += u.Count
			sum.Bytes += u.Bytes
		}
		close(done)
	}()
	items, pages, err := listAcrossRegions(ctx, c, named, func(ctx context.Context, region string) ([]T, RegionPage, error) {
		items, page, u, err := one(ctx, region)
		if err == nil {
			usages <- u
		}
		return items, page, err
	})
	close(usages)
	<-done
	return items, pages, err
}

// Get returns one snapshot.
func (s *SnapshotsService) Get(ctx context.Context, snapshotID string, opts ...CallOption) (*Snapshot, error) {
	e, err := seg(snapshotID)
	if err != nil {
		return nil, err
	}
	region := s.c.regionOf(applyCall(opts).region)
	return getResource[Snapshot](ctx, s.c, request{method: http.MethodGet, path: "/api/v1/sandbox/snapshots/" + e, region: region}, region)
}

// Delete deletes the snapshot and its stored copy; sandboxes started from it keep running.
func (s *SnapshotsService) Delete(ctx context.Context, snapshotID string, opts ...CallOption) error {
	e, err := seg(snapshotID)
	if err != nil {
		return err
	}
	return s.c.doJSON(ctx, request{method: http.MethodDelete, path: "/api/v1/sandbox/snapshots/" + e, region: applyCall(opts).region}, nil)
}

// TemplatesService manages sandbox templates: an image with its default resources.
type TemplatesService struct{ c *Client }

// Template is one sandbox template.
type Template struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	// Status is "building", "ready" or "failed".
	Status     string `json:"status"`
	DiskSizeMB int    `json:"disk_size_mb,omitempty"`
	MemSizeMB  int    `json:"mem_size_mb,omitempty"`
	CPUCount   int    `json:"cpu_count,omitempty"`
	// Image is the OCI image the template's sandboxes run, pinned by digest.
	Image      string `json:"image,omitempty"`
	SnapshotID string `json:"snapshot_id,omitempty"`
	CreatedBy  string `json:"created_by,omitempty"`
	CreatedAt  Time   `json:"created_at"`

	Region string          `json:"-"`
	Raw    json.RawMessage `json:"-"`
}

func (t *Template) attach(region string, raw json.RawMessage) { t.Region, t.Raw = region, raw }

// CreateTemplateParams create a template from an OCI image pinned by digest or from a snapshot.
type CreateTemplateParams struct {
	// Name is 2 to 64 lowercase letters, digits or hyphens.
	Name string `json:"name"`
	// Version is semver (server default 0.1.0).
	Version string `json:"version,omitempty"`
	// Image is an OCI image pinned by digest (name@sha256:...). Give this or SnapshotID.
	Image      string `json:"image,omitempty"`
	SnapshotID string `json:"snapshot_id,omitempty"`
	DiskMB     int    `json:"disk_size_mb,omitempty"`
	MemMB      int    `json:"mem_size_mb,omitempty"`
	CPUCount   int    `json:"cpu_count,omitempty"`
}

// TemplateBuildStatus says whether a template's image is building, ready or failed.
type TemplateBuildStatus struct {
	Status          string  `json:"status"`
	ProgressPercent float64 `json:"progress_percent"`
}

// Create creates a template.
func (t *TemplatesService) Create(ctx context.Context, p CreateTemplateParams, opts ...CallOption) (*Template, error) {
	region := t.c.regionOf(applyCall(opts).region)
	return getResource[Template](ctx, t.c, request{method: http.MethodPost, path: "/api/v1/sandbox/templates", body: p, region: region}, region)
}

// TemplateList is a list of templates, with one RegionPage per region read.
type TemplateList struct {
	Data  []Template
	Pages []RegionPage
}

// List lists the organization's templates and the built-in ones, of one region or of every live region.
func (t *TemplatesService) List(ctx context.Context, opts ...CallOption) (*TemplateList, error) {
	items, pages, err := listAcrossRegions(ctx, t.c, applyCall(opts).region, func(ctx context.Context, region string) ([]Template, RegionPage, error) {
		var raw struct {
			Data       []json.RawMessage `json:"data"`
			NextCursor *string           `json:"next_cursor"`
			HasMore    bool              `json:"has_more"`
		}
		if err := t.c.doJSON(ctx, request{method: http.MethodGet, path: "/api/v1/sandbox/templates", region: region}, &raw); err != nil {
			return nil, RegionPage{}, err
		}
		out, err := decodeAll[Template](raw.Data, region)
		page := RegionPage{HasMore: raw.HasMore}
		if raw.NextCursor != nil {
			page.NextCursor = *raw.NextCursor
		}
		return out, page, err
	})
	if err != nil {
		return nil, err
	}
	return &TemplateList{Data: items, Pages: pages}, nil
}

// Get returns one template.
func (t *TemplatesService) Get(ctx context.Context, templateID string, opts ...CallOption) (*Template, error) {
	e, err := seg(templateID)
	if err != nil {
		return nil, err
	}
	region := t.c.regionOf(applyCall(opts).region)
	return getResource[Template](ctx, t.c, request{method: http.MethodGet, path: "/api/v1/sandbox/templates/" + e, region: region}, region)
}

// Delete removes a template; sandboxes already started from it keep running.
func (t *TemplatesService) Delete(ctx context.Context, templateID string, opts ...CallOption) error {
	e, err := seg(templateID)
	if err != nil {
		return err
	}
	return t.c.doJSON(ctx, request{method: http.MethodDelete, path: "/api/v1/sandbox/templates/" + e, region: applyCall(opts).region}, nil)
}

// BuildStatus says whether the template's image is building, ready or failed.
func (t *TemplatesService) BuildStatus(ctx context.Context, templateID string, opts ...CallOption) (*TemplateBuildStatus, error) {
	e, err := seg(templateID)
	if err != nil {
		return nil, err
	}
	var out TemplateBuildStatus
	if err := t.c.doJSON(ctx, request{method: http.MethodGet, path: "/api/v1/sandbox/templates/" + e + "/build-status", region: applyCall(opts).region}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PolicyService reads and changes the organization's sandbox policy.
type PolicyService struct{ c *Client }

// SandboxPolicy is the organization's sandbox policy: limits, egress allowlist and presets.
// Nullable limits are nil when the server sends none.
type SandboxPolicy struct {
	MaxConcurrent        int      `json:"max_concurrent"`
	MaxExecTimeSeconds   int      `json:"max_exec_time_sec"`
	MaxMemMB             int      `json:"max_mem_mb"`
	MaxCPU               int      `json:"max_cpu"`
	MaxDiskMB            *int     `json:"max_disk_mb"`
	MaxWorkspacesPerUser *int     `json:"max_workspaces_per_user"`
	MaxCPUCoresPerUser   *int     `json:"max_cpu_cores_per_user"`
	MaxMemoryGBPerUser   *int     `json:"max_memory_gb_per_user"`
	EgressAllowlist      []string `json:"egress_allowlist"`
	AllowedProviders     []string `json:"allowed_providers"`
	EgressPresets        []string `json:"egress_presets"`
	// Hibernation is "default", "on" or "off".
	Hibernation string `json:"hibernation,omitempty"`

	Region string          `json:"-"`
	Raw    json.RawMessage `json:"-"`
}

func (p *SandboxPolicy) attach(region string, raw json.RawMessage) { p.Region, p.Raw = region, raw }

// SandboxPolicyUpdate changes the members that are set; the rest keep their values. The server
// decides what is allowed.
type SandboxPolicyUpdate struct {
	MaxConcurrent        *int `json:"max_concurrent,omitempty"`
	MaxExecTimeSeconds   *int `json:"max_exec_time_sec,omitempty"`
	MaxMemMB             *int `json:"max_mem_mb,omitempty"`
	MaxCPU               *int `json:"max_cpu,omitempty"`
	MaxDiskMB            *int `json:"max_disk_mb,omitempty"`
	MaxWorkspacesPerUser *int `json:"max_workspaces_per_user,omitempty"`
	MaxCPUCoresPerUser   *int `json:"max_cpu_cores_per_user,omitempty"`
	MaxMemoryGBPerUser   *int `json:"max_memory_gb_per_user,omitempty"`
	// The lists: nil leaves the list alone, an empty non-nil slice clears it.
	EgressAllowlist  []string `json:"egress_allowlist"`
	AllowedProviders []string `json:"allowed_providers"`
	EgressPresets    []string `json:"egress_presets"`
	// Hibernation between tool calls: "default", "on" or "off".
	Hibernation string `json:"hibernation,omitempty"`
}

// Get returns the organization's sandbox policy.
func (p *PolicyService) Get(ctx context.Context, opts ...CallOption) (*SandboxPolicy, error) {
	region := p.c.regionOf(applyCall(opts).region)
	return getResource[SandboxPolicy](ctx, p.c, request{method: http.MethodGet, path: "/api/v1/sandbox/policy", region: region}, region)
}

// Set changes the members you set.
func (p *PolicyService) Set(ctx context.Context, u SandboxPolicyUpdate, opts ...CallOption) (*SandboxPolicy, error) {
	region := p.c.regionOf(applyCall(opts).region)
	return getResource[SandboxPolicy](ctx, p.c, request{method: http.MethodPut, path: "/api/v1/sandbox/policy", body: u, region: region}, region)
}

// AccountService reads usage and the region list.
type AccountService struct{ c *Client }

// Usage is the usage of the month across every region.
type Usage struct {
	Month           string          `json:"month"`
	VCPUSecondsUsed float64         `json:"vcpu_seconds_used"`
	VCPUSecondsLeft float64         `json:"vcpu_seconds_left"`
	RunningBoxes    int             `json:"running_boxes"`
	RunningByRegion map[string]int  `json:"running_by_region"`
	Raw             json.RawMessage `json:"-"`
}

func (u *Usage) attach(_ string, raw json.RawMessage) { u.Raw = raw }

// Usage returns the usage of the month across every region: vCPU seconds used and left, and the
// boxes running.
func (a *AccountService) Usage(ctx context.Context, opts ...CallOption) (*Usage, error) {
	return getResource[Usage](ctx, a.c, request{method: http.MethodGet, path: "/api/v1/sandscale/usage", region: applyCall(opts).region}, "")
}

// RegionInfo is one region the server lists.
type RegionInfo struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	APIURL string `json:"api_url,omitempty"`
}

// Regions returns the regions the server lists (public; no credential is sent).
func (a *AccountService) Regions(ctx context.Context) ([]RegionInfo, error) {
	var raw struct {
		Regions []RegionInfo `json:"regions"`
	}
	if err := a.c.doJSON(ctx, request{method: http.MethodGet, path: "/api/v1/regions", noAuth: true, noOrg: true}, &raw); err != nil {
		return nil, err
	}
	return raw.Regions, nil
}
