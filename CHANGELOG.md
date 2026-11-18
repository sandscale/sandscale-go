# Changelog

## 1.0.0 - 2026-11-18

First release of `github.com/sandscale/sandscale-go` under the Apache-2.0 licence.

- Sandboxes: create, get, list (every live region), stop, pause, resume, keep awake, snapshot,
  exec with live output, run log streaming that resumes after a dropped connection, and files
  (write, read, list).
- Workspaces: create, get, list, update, delete, start, stop, rebuild, connect info, open links.
- Webhooks: list, create (the signing secret is shown once and never printed), delete, and
  signature verification (`VerifySignature`, `VerifyRequest`).
- Organization snapshots, templates and sandbox policy; usage and the region list.
- Typed errors for every coded API error: `*APIError` matches `ErrNotFound`, `ErrLimitExceeded`,
  `ErrRateLimited`, `ErrEntitlement`, `ErrRegion`, `ErrKillSwitch`, `ErrSandboxWaking` and the
  other sentinels with `errors.Is`, and carries the server's code, message, request id,
  details, region and `Retry-After`.
- A region per client and per call, default base URL `https://api.sandscale.dev`, retries of
  safe calls only, redirects refused, context on every call, no dependencies outside the
  standard library.
