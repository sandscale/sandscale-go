// Copyright 2026 Neural Inverse
// SPDX-License-Identifier: Apache-2.0

// Package sandscale is the Go client for the Sandscale API (https://api.sandscale.dev):
// sandboxes, workspaces, webhooks, snapshots, templates, sandbox policy and usage.
//
// The server decides everything: permissions, plan limits, quotas, entitlements, kill switches
// and regions. The client sends your request as you (your API key or your own sign-in token) and
// hands back the server's answer, including its error code and message as an *APIError.
//
//	client, err := sandscale.NewClient(sandscale.WithAPIKey(os.Getenv("SANDSCALE_API_KEY")))
//	if err != nil { ... }
//	box, err := client.Sandboxes.Create(ctx, sandscale.CreateSandboxParams{Template: "builtin:python"})
//	res, err := client.Sandboxes.Exec(ctx, box.ID, sandscale.ExecParams{Command: []string{"python3", "--version"}},
//		sandscale.WithRegion(box.Region))
//
// Every call takes a context first. Calls accept CallOptions, of which WithRegion sends the call
// to one region. Errors from the API are *APIError values that match the sentinel errors
// (ErrNotFound, ErrLimitExceeded, ...) with errors.Is.
package sandscale
