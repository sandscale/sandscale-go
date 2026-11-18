# Releasing sandscale-go

A Go module release is a git tag: there is nothing to publish and no credential to keep. Once
`vX.Y.Z` is pushed, `go get github.com/sandscale/sandscale-go@vX.Y.Z` works and the Go module
proxy and checksum database record it. A tag is permanent: the proxy never forgets a version, so
a bad version is fixed by a new one (and marked with a `retract` directive in `go.mod`).

This repository is the source of truth for the Go SDK (unlike sandscale-js and sandscale-python,
which mirror the Keystone source).

```bash
# 1. Update CHANGELOG.md and const Version in version.go to X.Y.Z, commit on main.
# 2. Check:
test -z "$(gofmt -l .)" && go vet ./... && go test -race -count=1 ./...
# 3. Tag and push:
git tag vX.Y.Z && git push origin vX.Y.Z
# 4. Warm the proxy and verify:
GOPROXY=https://proxy.golang.org go list -m github.com/sandscale/sandscale-go@vX.Y.Z
```

Breaking changes go in a new major version (`/v2` module path), never in a 1.x release.
