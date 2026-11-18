// Copyright 2026 Neural Inverse
// SPDX-License-Identifier: Apache-2.0

package sandscale_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	sandscale "github.com/sandscale/sandscale-go"
)

// These examples are compiled, not run: they need a Sandscale API key.

func Example() {
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
		OnStdout: func(s string) { fmt.Print(s) },
	}, sandscale.WithRegion(box.Region))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("exit code", res.ExitCode)
}

func ExampleAPIError() {
	ctx := context.Background()
	client, _ := sandscale.NewClient(sandscale.WithAPIKey("key"))
	_, err := client.Sandboxes.Create(ctx, sandscale.CreateSandboxParams{})
	switch {
	case errors.Is(err, sandscale.ErrLimitExceeded):
		// a quota or plan limit (rate limits match too)
	case errors.Is(err, sandscale.ErrKillSwitch):
		// stopped by a kill switch
	}
	if api, ok := sandscale.AsAPIError(err); ok {
		log.Println(api.Code, api.RequestID, api.RetryAfter)
	}
}

func ExampleVerifyRequest() {
	http.HandleFunc("/hooks/sandscale", func(w http.ResponseWriter, r *http.Request) {
		body, err := sandscale.VerifyRequest(r, os.Getenv("SANDSCALE_WEBHOOK_SECRET"))
		if err != nil {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		_ = body // parse the verified payload
	})
}
