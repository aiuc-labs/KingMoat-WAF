package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
)

// TestHealthSnapshot pins the data-plane health snapshot contract the embedded
// console consumes: one entry per configured site keyed by its primary domain,
// one node per upstream target, healthy before any failure.
func TestHealthSnapshot(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer up.Close()

	cfg := &config.Config{
		ListenHTTP: ":0",
		Sites: []config.Site{{
			Domains:  []string{"h.local", "alias.local"},
			Upstream: config.Upstream{Nodes: []config.UpstreamNode{{Address: trimScheme(up.URL)}}},
		}},
	}
	h, err := NewReloadableObserved(cfg, &captureStore{}, nil, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	snap := h.HealthSnapshot()
	nodes, ok := snap["h.local"]
	if !ok {
		t.Fatalf("snapshot missing primary domain key: %+v", snap)
	}
	if len(nodes) != 1 || !nodes[0].Healthy {
		t.Fatalf("nodes = %+v, want one healthy node", nodes)
	}
	if !strings.HasPrefix(nodes[0].Address, "http://") {
		t.Fatalf("address = %q, want scheme-prefixed target", nodes[0].Address)
	}
}
