// Copyright 2026 Neural Inverse
// SPDX-License-Identifier: Apache-2.0

package sandscale

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Every route the tests call is recorded. When SANDSCALE_ROUTE_INVENTORY names the server's
// route inventory files (colon separated; the source repository of the server sets it), the run
// fails if the server does not mount one of them. Without it the check is skipped.

var (
	routeMu   sync.Mutex
	routeSeen = map[string]bool{}
	idSegment = regexp.MustCompile(`/(instances|runs|templates|snapshots|webhooks|workspaces|ports|orgs|backups)/[^/]+`)
	routeLine = regexp.MustCompile(`^(?:\S+ )?((?:GET|POST|PUT|PATCH|DELETE) /\S*)`)
	braces    = regexp.MustCompile(`\{[^}/]*\}`)
)

func logRoute(method, path string) {
	routeMu.Lock()
	defer routeMu.Unlock()
	routeSeen[method+" "+idSegment.ReplaceAllString(path, "/$1/{}")] = true
}

func TestMain(m *testing.M) {
	code := m.Run()
	if inv := os.Getenv("SANDSCALE_ROUTE_INVENTORY"); inv != "" && code == 0 {
		mounted := map[string]bool{}
		for _, file := range strings.Split(inv, ":") {
			f, err := os.Open(file)
			if err != nil {
				fmt.Fprintln(os.Stderr, "route inventory:", err)
				os.Exit(1)
			}
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				if m := routeLine.FindStringSubmatch(sc.Text()); m != nil {
					mounted[braces.ReplaceAllString(m[1], "{}")] = true
				}
			}
			f.Close()
		}
		var missing []string
		for r := range routeSeen {
			if r == "GET /api/v1/regions" || mounted[r] {
				continue
			}
			missing = append(missing, r)
		}
		sort.Strings(missing)
		fmt.Printf("route contract: %d routes called, %d not mounted by the server\n", len(routeSeen), len(missing))
		if len(missing) > 0 {
			fmt.Fprintln(os.Stderr, "routes called that the server does not mount:\n  "+strings.Join(missing, "\n  "))
			os.Exit(1)
		}
		if os.Getenv("SANDSCALE_ROUTE_LIST") != "" {
			var all []string
			for r := range routeSeen {
				all = append(all, r)
			}
			sort.Strings(all)
			fmt.Println(strings.Join(all, "\n"))
		}
	}
	os.Exit(code)
}

var _ = testing.Short
