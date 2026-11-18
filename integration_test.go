// Copyright 2026 Neural Inverse
// SPDX-License-Identifier: Apache-2.0

package sandscale

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestLiveRegions reads the public region list of the real API. It runs only when
// SANDSCALE_LIVE=1 (it needs the network, no credential).
func TestLiveRegions(t *testing.T) {
	if os.Getenv("SANDSCALE_LIVE") != "1" {
		t.Skip("set SANDSCALE_LIVE=1 to read the real region list")
	}
	c, err := NewClient(WithAPIKey("unused-for-public-calls"))
	if err != nil {
		t.Fatal(err)
	}
	regions, err := c.Account.Regions(ctx())
	if err != nil || len(regions) == 0 {
		t.Fatalf("%v %v", regions, err)
	}
	t.Logf("live regions: %+v", regions)
	live, err := c.liveRegions(ctx())
	if err != nil || len(live) == 0 {
		t.Fatalf("live regions %v %v", live, err)
	}
	t.Logf("front door live regions: %v", live)
}

// TestIntegration runs against the real Sandscale API only when SANDSCALE_API_KEY is set (it
// starts and stops one small sandbox, which uses credits). SANDSCALE_BASE_URL, SANDSCALE_ORG_ID
// and SANDSCALE_REGION are honoured. Nothing secret is printed.
func TestIntegration(t *testing.T) {
	if os.Getenv("SANDSCALE_API_KEY") == "" {
		t.Skip("set SANDSCALE_API_KEY to run against the real API")
	}
	c, err := NewClient(WithDefaultRegion(os.Getenv("SANDSCALE_REGION")))
	if err != nil {
		t.Fatal(err)
	}
	box, err := c.Sandboxes.Create(ctx(), CreateSandboxParams{Template: "builtin:base", TTLSeconds: 300})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := c.Sandboxes.Stop(ctx(), box.ID, WithRegion(box.Region)); err != nil {
			t.Errorf("stop: %v", err)
		}
	}()
	var live []string
	res, err := c.Sandboxes.Exec(ctx(), box.ID, ExecParams{Shell: "echo hello && echo oops >&2 && exit 3", Timeout: 60 * time.Second,
		OnStdout: func(s string) { live = append(live, s) }, OnStderr: func(s string) { live = append(live, s) }}, WithRegion(box.Region))
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 3 || !strings.Contains(res.Stdout, "hello") || !strings.Contains(strings.Join(live, ""), "hello") {
		t.Fatalf("%+v %v", res, live)
	}
	if err := c.Sandboxes.WriteFile(ctx(), box.ID, "/workspace/hello.txt", []byte("hi"), WithRegion(box.Region)); err != nil {
		t.Fatal(err)
	}
	data, err := c.Sandboxes.ReadFile(ctx(), box.ID, "/workspace/hello.txt", WithRegion(box.Region))
	if err != nil || string(data) != "hi" {
		t.Fatalf("%q %v", data, err)
	}
	list, err := c.Sandboxes.List(ctx(), ListSandboxesParams{}, WithRegion(box.Region))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range list.Data {
		found = found || s.ID == box.ID
	}
	if !found {
		t.Fatal("the new sandbox is not in the list")
	}
}
