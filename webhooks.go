// Copyright 2026 Neural Inverse
// SPDX-License-Identifier: Apache-2.0

package sandscale

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// SignatureHeader is the header that carries a delivery's signature: "sha256=<hex>", the
// HMAC-SHA256 of the raw request body under the webhook's secret.
const SignatureHeader = "X-Keystone-Signature"

// Webhook events of sandboxes.
const (
	EventInstanceCreated    = "instance.created"
	EventInstanceTerminated = "instance.terminated"
	EventRunCompleted       = "run.completed"
	EventSnapshotCreated    = "snapshot.created"
)

// WebhooksService manages webhook endpoints for sandbox events.
type WebhooksService struct{ c *Client }

// Webhook is one webhook endpoint. The signing secret is never part of it.
type Webhook struct {
	ID        string   `json:"id"`
	URL       string   `json:"url"`
	Events    []string `json:"events"`
	Active    bool     `json:"active"`
	CreatedAt Time     `json:"created_at"`
	UpdatedAt Time     `json:"updated_at"`

	Region string          `json:"-"`
	Raw    json.RawMessage `json:"-"`
}

func (w *Webhook) attach(region string, raw json.RawMessage) {
	w.Region = region
	// The raw answer never keeps the signing secret.
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) == nil {
		delete(m, "secret")
		if b, err := json.Marshal(m); err == nil {
			raw = b
		}
	}
	w.Raw = raw
}

// CreatedWebhook is a webhook as created. The signing secret the server shows once is read with
// Secret; it is in no JSON, String or log output of this value.
type CreatedWebhook struct {
	Webhook
	secret string
}

// Secret returns the signing secret. The server shows it once: store it at once.
func (w CreatedWebhook) Secret() string { return w.secret }

// String never includes the secret.
func (w CreatedWebhook) String() string { return fmt.Sprintf("Webhook{%s %s}", w.ID, w.URL) }

// CreateWebhookParams register an endpoint.
type CreateWebhookParams struct {
	URL string `json:"url"`
	// Events defaults to every event.
	Events []string `json:"events,omitempty"`
	// Secret is your own signing secret; default: the server generates one.
	Secret string `json:"secret,omitempty"`
}

// List lists the webhook endpoints.
func (w *WebhooksService) List(ctx context.Context, opts ...CallOption) ([]Webhook, error) {
	region := w.c.regionOf(applyCall(opts).region)
	var raw struct {
		Webhooks []json.RawMessage `json:"webhooks"`
	}
	if err := w.c.doJSON(ctx, request{method: http.MethodGet, path: "/api/v1/sandbox/webhooks", region: region}, &raw); err != nil {
		return nil, err
	}
	return decodeAll[Webhook](raw.Webhooks, region)
}

// Create registers an endpoint. The signing secret is on the result's Secret method, once.
func (w *WebhooksService) Create(ctx context.Context, p CreateWebhookParams, opts ...CallOption) (*CreatedWebhook, error) {
	region := w.c.regionOf(applyCall(opts).region)
	_, body, err := w.c.send(ctx, request{method: http.MethodPost, path: "/api/v1/sandbox/webhooks", body: p, region: region})
	if err != nil {
		return nil, err
	}
	out := &CreatedWebhook{}
	if err := json.Unmarshal(body, &out.Webhook); err != nil {
		return nil, fmt.Errorf("sandscale: decode webhook: %w", err)
	}
	var s struct {
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal(body, &s)
	out.secret = s.Secret
	out.Webhook.attach(region, body)
	return out, nil
}

// Delete removes an endpoint.
func (w *WebhooksService) Delete(ctx context.Context, webhookID string, opts ...CallOption) error {
	e, err := seg(webhookID)
	if err != nil {
		return err
	}
	return w.c.doJSON(ctx, request{method: http.MethodDelete, path: "/api/v1/sandbox/webhooks/" + e, region: applyCall(opts).region}, nil)
}

// VerifySignature reports whether signature (the SignatureHeader value, "sha256=<hex>") is the
// HMAC-SHA256 of body under secret. Pass the body exactly as received, before any JSON parsing.
// The comparison is constant time; a missing or malformed signature is false. The current
// signing carries no timestamp.
func VerifySignature(signature string, body []byte, secret string) bool {
	if secret == "" || !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	given, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(signature[len("sha256="):])))
	if err != nil || len(given) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), given)
}

// WebhookEvent is the body of a delivery. Data is the event-specific payload.
type WebhookEvent struct {
	// ID is the unique delivery id; use it to ignore a redelivery you already handled.
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	OrgID      string          `json:"org_id"`
	OccurredAt Time            `json:"occurred_at"`
	Data       json.RawMessage `json:"data"`
}

// ParseEvent decodes a verified delivery body (see VerifyRequest).
func ParseEvent(body []byte) (*WebhookEvent, error) {
	var e WebhookEvent
	if err := json.Unmarshal(body, &e); err != nil {
		return nil, fmt.Errorf("sandscale: decode webhook event: %w", err)
	}
	return &e, nil
}

// ErrInvalidSignature is returned by VerifyRequest when the delivery is not signed by secret.
var ErrInvalidSignature = errors.New("sandscale: webhook signature does not match")

// MaxWebhookBody is the most VerifyRequest reads from a delivery.
const MaxWebhookBody = 1 << 20

// VerifyRequest reads a delivery's body (at most MaxWebhookBody) and checks its signature header
// against secret. It returns the body only when the signature is valid, so a handler never
// parses an unsigned payload.
func VerifyRequest(r *http.Request, secret string) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxWebhookBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxWebhookBody {
		return nil, errors.New("sandscale: webhook body too large")
	}
	if !VerifySignature(r.Header.Get(SignatureHeader), body, secret) {
		return nil, ErrInvalidSignature
	}
	return body, nil
}
