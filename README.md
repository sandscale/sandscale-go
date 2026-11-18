# sandscale-go

Go SDK for [Sandscale](https://sandscale.dev): sandboxes, workspaces, webhooks, snapshots,
templates, sandbox policy and usage over the Sandscale API (`https://api.sandscale.dev`).
Standard library only; Go 1.22 or later.

The server decides everything: permissions, plan limits, quotas, entitlements, kill switches and
regions. The SDK sends your request as you (your API key or your own sign-in token) and hands
back the server's answer, including its error code and message.

Documentation: https://sandscale.dev/docs. Licensed under Apache-2.0.

## Install

```bash
go get github.com/sandscale/sandscale-go
```

## Quick start

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	sandscale "github.com/sandscale/sandscale-go"
)

func main() {
	ctx := context.Background()
	client, err := sandscale.NewClient(sandscale.WithAPIKey(os.Getenv("SANDSCALE_API_KEY")))
	if err != nil {
		log.Fatal(err)
	}

	box, err := client.Sandboxes.Create(ctx, sandscale.CreateSandboxParams{Template: "builtin:python", TTLSeconds: 600})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Sandboxes.Stop(ctx, box.ID, sandscale.WithRegion(box.Region))

	res, err := client.Sandboxes.Exec(ctx, box.ID, sandscale.ExecParams{
		Shell:    `python3 -c "print(6*7)"`,
		OnStdout: func(s string) { fmt.Print(s) }, // live output
	}, sandscale.WithRegion(box.Region))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("exit code", res.ExitCode)
}
```

## Authentication and options

| Option | Environment | |
|---|---|---|
| `WithAPIKey` | `SANDSCALE_API_KEY` | A Sandscale API key. |
| `WithTokenSource` | | The person's own sign-in access token; called before every request, so it can refresh. |
| `WithOrgID` | `SANDSCALE_ORG_ID` | Sent as `X-Org-ID`; required by workspace calls. |
| `WithBaseURL` | `SANDSCALE_BASE_URL` | Default `https://api.sandscale.dev`. `https` only (plain `http` only to a loopback host). |
| `WithDefaultRegion` | | `us` or `eu`; the region of every call that does not name one. |
| `WithHTTPClient`, `WithTimeout`, `WithMaxRetries` | | Transport settings (timeout default 60 s, 2 retries of safe calls). |

Credentials are held in memory and sent only to the configured API origin and the region origins;
redirects are refused so a credential never follows one.

## Regions

One account works in every Sandscale region. Pass `sandscale.WithRegion("us")` or `"eu"` to a call,
or set a default with `WithDefaultRegion`. Resources report the region they live in
(`box.Region`); pass it to later calls on them. List calls without a region read every live region
and return one `RegionPage` per region; a region that cannot be read is reported in
`RegionPage.Err` while the others' items are still returned.

## API

| Service | Calls |
|---|---|
| `client.Sandboxes` | `Create`, `Get`, `List`, `Stop`, `Pause`, `Resume`, `KeepAwake`, `Snapshot`, `ListSnapshots`, `Exec`, `StreamLogs`, `WriteFile`, `ReadFile`, `ListFiles` |
| `client.Workspaces` | `Create`, `Get`, `List`, `Update`, `Delete`, `Start`, `Stop`, `Rebuild`, `ConnectInfo`, `OpenLink` |
| `client.Webhooks` | `List`, `Create`, `Delete`; package functions `VerifySignature`, `VerifyRequest`, `ParseEvent` |
| `client.Snapshots` | `List`, `Get`, `Delete` |
| `client.Templates` | `Create`, `List`, `Get`, `Delete`, `BuildStatus` |
| `client.Policy` | `Get`, `Set` |
| `client.Account` | `Usage`, `Regions` |

Every call takes a `context.Context` first. Each resource has a `Raw` field with the server's full
answer.

## Webhooks

```go
wh, err := client.Webhooks.Create(ctx, sandscale.CreateWebhookParams{
	URL: "https://example.com/hooks/sandscale", Events: []string{sandscale.EventRunCompleted},
})
secret := wh.Secret() // shown once: store it now

http.HandleFunc("/hooks/sandscale", func(w http.ResponseWriter, r *http.Request) {
	body, err := sandscale.VerifyRequest(r, secret) // reads the raw body and checks X-Keystone-Signature
	if err != nil {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	// parse body
})
```

## Errors

An error from the API is an `*APIError` with the server's `Code`, `Message`, `RequestID`,
`Details`, `Region` and `RetryAfter`. Match a family with `errors.Is`:

```go
_, err := client.Sandboxes.Create(ctx, params)
switch {
case errors.Is(err, sandscale.ErrLimitExceeded): // quota or plan limit (rate limits match too)
case errors.Is(err, sandscale.ErrEntitlement):   // the plan does not include this
case errors.Is(err, sandscale.ErrKillSwitch):    // stopped by a kill switch
case errors.Is(err, sandscale.ErrRegion):        // wrong or unavailable region
case errors.Is(err, sandscale.ErrSandboxWaking): // retry after the Retry-After
}
if api, ok := sandscale.AsAPIError(err); ok { log.Println(api.Code, api.RequestID) }
```

Sentinels: `ErrInvalidRequest`, `ErrAuthentication`, `ErrPermissionDenied`, `ErrNotFound`,
`ErrConflict`, `ErrLimitExceeded`, `ErrRateLimited`, `ErrEntitlement`, `ErrRegion`,
`ErrKillSwitch`, `ErrServer`, `ErrServiceUnavailable`, `ErrSandboxWaking`. A failed connection is
a `*ConnectionError`; a bad configuration is a `*ConfigError`.

## Retries

Only safe calls (`GET`) are retried, at most twice by default, after a connection error, 429,
502, 503 or 504, with exponential backoff and full jitter, or the server's `Retry-After` (at most
60 s). Kill switch, entitlement and region refusals are never retried. Calls that change
something are sent once.

## Tests

```bash
go test -race ./...                       # unit tests against local httptest servers
SANDSCALE_LIVE=1 go test -run Live ./...  # reads the real public region list
SANDSCALE_API_KEY=... go test ./...       # also the integration test (starts and stops one sandbox)
```
