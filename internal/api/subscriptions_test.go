package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"xrayrelay/internal/model"
	"xrayrelay/internal/store"
)

func TestSubscriptionSSRFRejectsPrivateReservedAndMappedAddresses(t *testing.T) {
	blocked := []string{
		"http://127.0.0.1/", "http://localhost/", "https://service.local/", "http://10.1.2.3/",
		"http://169.254.169.254/latest/meta-data/", "http://100.64.0.1/", "http://192.0.2.1/",
		"http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://[fc00::1]/", "http://[fe80::1]/",
		"file:///etc/passwd", "https://owner@example.com/", "http://example.com/#fragment",
	}
	for _, raw := range blocked {
		if _, err := validateSubscriptionURL(raw); err == nil {
			t.Errorf("unsafe target was accepted: %s", raw)
		}
	}
	if !publicAddress(net.IP{8, 8, 8, 8}) || publicAddress(net.IP{10, 0, 0, 1}) || publicAddress(net.ParseIP("::ffff:127.0.0.1")) {
		t.Fatal("IP classification did not unmap or reject private addresses")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if connection, err := safeSubscriptionDial(ctx, "tcp", "localhost:80"); err == nil {
		connection.Close()
		t.Fatal("DNS resolution allowed a loopback target")
	}
	var called atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
	}))
	defer server.Close()
	if _, err := fetchSubscription(context.Background(), server.URL); !errors.Is(err, errUnsafeSubscription) || called.Load() {
		t.Fatal("private subscription request reached the local server")
	}
}

func TestDeletingSubscriptionKeepsUpstreamsAndReferences(t *testing.T) {
	s, cookie := fixture(t, nil)
	sub := model.Subscription{ID: "source", Name: "Source", URL: "https://example.com/sub", Count: 1}
	upstream := testUpstream(t)
	upstream.ID, upstream.SourceID = "source-upstream", sub.ID
	if err := s.store.Commit(context.Background(), store.Changes{Upstreams: []model.Upstream{upstream}, Subscriptions: []model.Subscription{sub}}); err != nil {
		t.Fatal(err)
	}
	result := decodeResponse[struct {
		Kept int `json:"kept_upstreams"`
	}](t, request(t, s, "DELETE", "/api/subscriptions/"+sub.ID, nil, cookie), http.StatusOK)
	if result.Kept != 1 {
		t.Fatal("subscription deletion did not explain retained upstreams")
	}
	state, err := s.store.State(context.Background())
	if err != nil || len(state.Upstreams) != 1 || state.Upstreams[0].SourceID != "" || len(state.Subscriptions) != 0 {
		t.Fatal("subscription deletion lost imported upstreams")
	}
	copy := upstream
	copy.Name = "Changed display name"
	if upstreamIdentity(copy) != upstreamIdentity(upstream) {
		t.Fatal("subscription identity depends on display name")
	}
}
