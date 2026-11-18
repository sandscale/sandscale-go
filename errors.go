// Copyright 2026 Neural Inverse
// SPDX-License-Identifier: Apache-2.0

package sandscale

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Kind sorts an API answer into a family, so callers can handle limits, entitlement, region and
// kill-switch refusals without matching code strings. The server decides every refusal; the SDK
// never refuses a call on its own.
type Kind int

const (
	// KindUnknown is an answer that fits no family (for example an unexpected 3xx or 4xx).
	KindUnknown Kind = iota
	// KindInvalidRequest is 400, 413 or 422: the request was refused as invalid.
	KindInvalidRequest
	// KindAuthentication is 401: the API key or token is missing, expired, revoked or of another region.
	KindAuthentication
	// KindPermissionDenied is 403: the caller may not do this (role, policy, host access rules).
	KindPermissionDenied
	// KindNotFound is 404: not found, or not visible to the caller.
	KindNotFound
	// KindConflict is 409: the resource is not in a state that allows the call (paused, ended, busy).
	KindConflict
	// KindLimitExceeded is a plan, quota or usage limit refusing the call (402, or a quota or limit code).
	KindLimitExceeded
	// KindRateLimited is 429: too many requests; retry after APIError.RetryAfter.
	KindRateLimited
	// KindEntitlement is the organization's plan not including this, or payment being required.
	KindEntitlement
	// KindRegion is a call sent to a region that cannot serve it (wrong region, region unavailable).
	KindRegion
	// KindKillSwitch is a kill switch (the organization's or Sandscale's) stopping the call.
	KindKillSwitch
	// KindServer is a 5xx: the server could not answer the call.
	KindServer
	// KindServiceUnavailable is a 503: the service cannot answer now and says so.
	KindServiceUnavailable
	// KindSandboxWaking is a 503 sandbox_waking: the sandbox is resuming from a pause; retry after RetryAfter.
	KindSandboxWaking
)

var kindNames = map[Kind]string{
	KindUnknown: "unknown", KindInvalidRequest: "invalid request", KindAuthentication: "authentication",
	KindPermissionDenied: "permission denied", KindNotFound: "not found", KindConflict: "conflict",
	KindLimitExceeded: "limit exceeded", KindRateLimited: "rate limited", KindEntitlement: "not entitled",
	KindRegion: "region", KindKillSwitch: "kill switch", KindServer: "server error",
	KindServiceUnavailable: "service unavailable", KindSandboxWaking: "sandbox waking",
}

func (k Kind) String() string { return kindNames[k] }

type kindError struct{ kind Kind }

func (e kindError) Error() string { return "sandscale: " + e.kind.String() }

// Sentinel errors for errors.Is. An *APIError matches the sentinel of its Kind and of the
// families it belongs to: rate limited is also limit exceeded; sandbox waking is also service
// unavailable; service unavailable is also a server error.
var (
	ErrInvalidRequest     error = kindError{KindInvalidRequest}
	ErrAuthentication     error = kindError{KindAuthentication}
	ErrPermissionDenied   error = kindError{KindPermissionDenied}
	ErrNotFound           error = kindError{KindNotFound}
	ErrConflict           error = kindError{KindConflict}
	ErrLimitExceeded      error = kindError{KindLimitExceeded}
	ErrRateLimited        error = kindError{KindRateLimited}
	ErrEntitlement        error = kindError{KindEntitlement}
	ErrRegion             error = kindError{KindRegion}
	ErrKillSwitch         error = kindError{KindKillSwitch}
	ErrServer             error = kindError{KindServer}
	ErrServiceUnavailable error = kindError{KindServiceUnavailable}
	ErrSandboxWaking      error = kindError{KindSandboxWaking}
)

// APIError is the server's answer to a call that failed. It carries the server's own code and
// message.
type APIError struct {
	// Status is the HTTP status of the answer.
	Status int
	// Code is the server's error code, for example "quota_exceeded" or "kill_switch_engaged".
	Code string
	// Message is the server's message.
	Message string
	// RequestID is the server's request id, when it sent one; quote it when you contact support.
	RequestID string
	// Details is the structured detail the server sent (error.detail or error.details), if any.
	Details json.RawMessage
	// Region is the region the server names in the answer (wrong_region answers carry it).
	Region string
	// RetryAfter is how long the server asked to wait (Retry-After); zero when it did not say.
	RetryAfter time.Duration
	// Kind is the family of the answer.
	Kind Kind
}

func (e *APIError) Error() string {
	s := fmt.Sprintf("sandscale: %s (%s, HTTP %d)", e.Message, e.Code, e.Status)
	if e.RequestID != "" {
		s += " request_id=" + e.RequestID
	}
	return s
}

// Is makes errors.Is(err, sandscale.ErrNotFound) and the other sentinels work.
func (e *APIError) Is(target error) bool {
	t, ok := target.(kindError)
	if !ok {
		return false
	}
	switch {
	case e.Kind == t.kind:
		return true
	case t.kind == KindLimitExceeded:
		return e.Kind == KindRateLimited
	case t.kind == KindServiceUnavailable:
		return e.Kind == KindSandboxWaking
	case t.kind == KindServer:
		return e.Kind == KindServiceUnavailable || e.Kind == KindSandboxWaking
	}
	return false
}

// Retryable reports whether the same call may succeed a moment later: a 429, 502, 503 or 504
// answer that is not a kill switch, entitlement or region refusal.
func (e *APIError) Retryable() bool {
	switch e.Status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
	default:
		return false
	}
	return e.Kind != KindKillSwitch && e.Kind != KindEntitlement && e.Kind != KindRegion
}

// AsAPIError returns the *APIError in err's chain, if any.
func AsAPIError(err error) (*APIError, bool) {
	var e *APIError
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// ConnectionError means no answer was received: the connection failed or the call timed out.
type ConnectionError struct {
	Op  string
	Err error
}

func (e *ConnectionError) Error() string { return fmt.Sprintf("sandscale: %s: %v", e.Op, e.Err) }
func (e *ConnectionError) Unwrap() error { return e.Err }

// ConfigError is returned before any call when the client cannot be configured safely, or a call
// is missing an input it cannot work without (an organization id, an empty id).
type ConfigError struct{ Msg string }

func (e *ConfigError) Error() string { return "sandscale: " + e.Msg }

var (
	killSwitchCode = regexp.MustCompile(`(^|_)kill_switch`)
	quotaCode      = regexp.MustCompile(`(^|_)quota(_|$)|(^|_)limit(_|$)|limit_exceeded$`)
)

// classify sorts a server answer into its Kind.
func classify(status int, code string) Kind {
	switch {
	case killSwitchCode.MatchString(code):
		return KindKillSwitch
	case code == "wrong_region" || strings.HasPrefix(code, "region_"):
		return KindRegion
	case code == "sandbox_waking":
		return KindSandboxWaking
	case code == "entitlement_unavailable":
		return KindServiceUnavailable
	case code == "not_entitled" || code == "payment_required" || code == "service_not_entitled" ||
		strings.HasPrefix(code, "entitlement_") || strings.HasPrefix(code, "plan_") || strings.HasSuffix(code, "_not_in_plan"):
		return KindEntitlement
	case status == http.StatusTooManyRequests:
		return KindRateLimited
	case status == http.StatusPaymentRequired || quotaCode.MatchString(code):
		return KindLimitExceeded
	}
	switch status {
	case 400, 413, 422:
		return KindInvalidRequest
	case 401:
		return KindAuthentication
	case 403:
		return KindPermissionDenied
	case 404:
		return KindNotFound
	case 409:
		return KindConflict
	case 503:
		return KindServiceUnavailable
	}
	if status >= 500 {
		return KindServer
	}
	return KindUnknown
}

// parseError reads the server's error envelope: {"error": {"code", "message", "request_id",
// "detail" | "details", "region"}}; the wrong_region answer also carries code and region at the
// top level.
func parseError(status int, statusText string, body []byte, h http.Header, now time.Time) *APIError {
	e := &APIError{Status: status, Code: "http_" + strconv.Itoa(status), Message: statusText}
	if e.Message == "" {
		e.Message = "HTTP " + strconv.Itoa(status)
	}
	var top struct {
		Error      json.RawMessage `json:"error"`
		Code       string          `json:"code"`
		Message    string          `json:"message"`
		Region     string          `json:"region"`
		HomeRegion string          `json:"home_region"`
	}
	if json.Unmarshal(body, &top) == nil {
		var inner struct {
			Code      string          `json:"code"`
			Message   string          `json:"message"`
			RequestID string          `json:"request_id"`
			Detail    json.RawMessage `json:"detail"`
			Details   json.RawMessage `json:"details"`
			Region    string          `json:"region"`
		}
		hasInner := len(top.Error) > 0 && json.Unmarshal(top.Error, &inner) == nil
		if hasInner && inner.Code != "" {
			e.Code = inner.Code
		} else if top.Code != "" {
			e.Code = top.Code
		}
		if hasInner && inner.Message != "" {
			e.Message = inner.Message
		} else if top.Message != "" {
			e.Message = top.Message
		}
		if hasInner {
			e.RequestID = inner.RequestID
			if len(inner.Detail) > 0 && string(inner.Detail) != "null" {
				e.Details = inner.Detail
			}
			if len(inner.Details) > 0 && string(inner.Details) != "null" {
				e.Details = inner.Details
			}
		}
		switch {
		case hasInner && inner.Region != "":
			e.Region = inner.Region
		case top.Region != "":
			e.Region = top.Region
		default:
			e.Region = top.HomeRegion
		}
	}
	if e.RequestID == "" {
		e.RequestID = h.Get("X-Request-ID")
	}
	e.RetryAfter = parseRetryAfter(h.Get("Retry-After"), now)
	e.Kind = classify(status, e.Code)
	return e
}

// parseRetryAfter reads Retry-After (seconds or an HTTP date); zero when absent or unreadable.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.ParseFloat(v, 64); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs * float64(time.Second))
	}
	if at, err := http.ParseTime(v); err == nil {
		if d := at.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}
