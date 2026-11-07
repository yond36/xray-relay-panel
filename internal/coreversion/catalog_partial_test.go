package coreversion

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestLatestPageRemainsSelectableWhenOlderPageFails(t *testing.T) {
	var failOlder atomic.Bool
	failOlder.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" && failOlder.Load() {
			w.WriteHeader(503)
			return
		}
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
	now := time.Now()
	catalog := NewCatalog()
	catalog.source = server.URL
	catalog.client = server.Client()
	catalog.clock = func() time.Time { return now }
	first, err := catalog.List(context.Background(), false)
	if err != nil || len(first.Releases) != pageSize || !first.Stale || first.Error == "" {
		t.Fatalf("usable latest versions discarded: %+v %v", first, err)
	}
	failOlder.Store(false)
	now = now.Add(6 * time.Minute)
	complete, err := catalog.List(context.Background(), true)
	if err != nil || complete.Stale || complete.Error != "" || len(complete.Releases) != pageSize*maxPages {
		t.Fatalf("partial cache did not recover: %+v %v", complete, err)
	}
}
