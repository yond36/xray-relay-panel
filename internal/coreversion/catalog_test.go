package coreversion

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCatalogueCachingConditionalRefreshAndStaleFallback(t *testing.T) {
	var calls atomic.Int32
	var failing atomic.Bool
	var conditional atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Query().Get("per_page") != "50" || r.Header.Get("User-Agent") == "" {
			t.Error("missing bounded page size or identity")
		}
		if failing.Load() {
			w.WriteHeader(429)
			return
		}
		if r.Header.Get("If-None-Match") == `"revision-1"` {
			conditional.Store(true)
			w.WriteHeader(304)
			return
		}
		w.Header().Set("ETag", `"revision-1"`)
		fmt.Fprint(w, `[{"tag_name":"v26.10.31","name":"Stable","published_at":"2026-10-31T00:00:00Z"},{"tag_name":"v26.11.1-rc.1","name":"Candidate","prerelease":true},{"tag_name":"v1.8.24","draft":true},{"tag_name":"../../bad"},{"tag_name":"v26.10.31"}]`)
	}))
	defer server.Close()
	now := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	client := NewCatalog()
	client.source = server.URL
	client.client = server.Client()
	client.clock = func() time.Time { return now }
	client.forceInterval = time.Minute
	first, err := client.List(context.Background(), false)
	if err != nil || len(first.Releases) != 2 || first.Releases[0].Tag != "v26.10.31" || !first.Releases[1].Prerelease {
		t.Fatalf("bad catalogue: %+v %v", first, err)
	}
	first.Releases[0].Tag = "mutated"
	second, err := client.List(context.Background(), false)
	if err != nil || second.Releases[0].Tag != "v26.10.31" || calls.Load() != 1 {
		t.Fatal("cache not isolated or reused")
	}
	now = now.Add(2 * time.Minute)
	if _, err = client.List(context.Background(), true); err != nil || !conditional.Load() || calls.Load() != 2 {
		t.Fatal("conditional refresh failed")
	}
	failing.Store(true)
	now = now.Add(2 * time.Minute)
	stale, err := client.List(context.Background(), true)
	if err != nil || !stale.Stale || stale.Error == "" || len(stale.Releases) != 2 {
		t.Fatalf("stale cache discarded: %+v %v", stale, err)
	}
}

func TestCatalogueConcurrentColdRequestsShareFetch(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		fmt.Fprint(w, `[{"tag_name":"v26.10.31"}]`)
	}))
	defer server.Close()
	client := NewCatalog()
	client.source = server.URL
	client.client = server.Client()
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := client.List(context.Background(), false)
			if err != nil || len(result.Releases) != 1 {
				t.Errorf("shared fetch failed: %v", err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("cold cache made %d upstream requests", calls.Load())
	}
}
func TestCatalogueErrorWithoutCacheIsExplicitAndBackedOff(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(503) }))
	defer server.Close()
	client := NewCatalog()
	client.source = server.URL
	client.client = server.Client()
	for i := 0; i < 3; i++ {
		result, err := client.List(context.Background(), true)
		if err == nil || result.Error == "" || len(result.Releases) != 0 {
			t.Fatal("failure reported as available catalogue")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("error backoff did not limit calls: %d", calls.Load())
	}
}
func TestCatalogueFollowsBoundedPagination(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, "[")
		for i := 0; i < pageSize; i++ {
			if i > 0 {
				fmt.Fprint(w, ",")
			}
			fmt.Fprintf(w, `{"tag_name":"v26.%s.%d"}`, r.URL.Query().Get("page"), i)
		}
		fmt.Fprint(w, "]")
	}))
	defer server.Close()
	client := NewCatalog()
	client.source = server.URL
	client.client = server.Client()
	result, err := client.List(context.Background(), false)
	if err != nil || len(result.Releases) != maxPages*pageSize || calls.Load() != maxPages {
		t.Fatalf("unbounded or incomplete pagination: %d %d %v", len(result.Releases), calls.Load(), err)
	}
}
