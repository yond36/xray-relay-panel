package api

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"xrayrelay/internal/model"
	"xrayrelay/internal/store"
)

var errUnsafeSubscription = errors.New("订阅地址只允许公网 HTTP/HTTPS，不能访问本机、内网或保留地址")

var reservedNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 88, 99, 0}), 24), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"),
	netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, 0x01}), 32), netip.MustParsePrefix("2001:db8::/32"),
	netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, 0x02}), 16),
}

func publicAddress(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range reservedNetworks {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func validateSubscriptionURL(raw string) (*url.URL, error) {
	if len(raw) > 4096 || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, errUnsafeSubscription
	}
	value, err := url.Parse(raw)
	if err != nil || value.Host == "" || value.User != nil || value.Fragment != "" || value.Opaque != "" || value.Scheme != "http" && value.Scheme != "https" {
		return nil, errUnsafeSubscription
	}
	host := strings.ToLower(strings.TrimSuffix(value.Hostname(), "."))
	if !validHost(host) || strings.Contains(host, "%") || host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") || host == "metadata.google.internal" {
		return nil, errUnsafeSubscription
	}
	if ip := net.ParseIP(host); ip != nil && !publicAddress(ip) {
		return nil, errUnsafeSubscription
	}
	if port := value.Port(); port != "" {
		if _, err := net.LookupPort("tcp", port); err != nil {
			return nil, errUnsafeSubscription
		}
	}
	return value, nil
}

func safeSubscriptionDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errUnsafeSubscription
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("订阅域名解析失败")
	}
	if len(addresses) > 32 {
		return nil, errUnsafeSubscription
	}
	// Validate every DNS answer, then dial the literal address rather than
	// resolving a second time. Mixed public/private answers fail closed.
	for _, candidate := range addresses {
		if candidate.Zone != "" || !publicAddress(candidate.IP) {
			return nil, errUnsafeSubscription
		}
	}
	dialer := net.Dialer{Timeout: 8 * time.Second, KeepAlive: -1}
	var lastErr error
	for _, candidate := range addresses {
		connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(candidate.IP.String(), port))
		if err == nil {
			return connection, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

func fetchSubscription(ctx context.Context, rawURL string) (string, error) {
	parsed, err := validateSubscriptionURL(strings.TrimSpace(rawURL))
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	transport := &http.Transport{
		Proxy: nil, DialContext: safeSubscriptionDial, DisableCompression: true,
		TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		MaxResponseHeaderBytes: 32 << 10, MaxIdleConns: 2, DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: 25 * time.Second,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) > 3 {
				return errors.New("订阅重定向次数超限")
			}
			if _, err := validateSubscriptionURL(request.URL.String()); err != nil {
				return err
			}
			if len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && request.URL.Scheme != "https" {
				return errors.New("不允许 HTTPS 订阅降级重定向")
			}
			request.Header.Del("Referer")
			request.Header.Del("Authorization")
			request.Header.Del("Cookie")
			return nil
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return "", errUnsafeSubscription
	}
	request.Header.Set("User-Agent", "xray-relay-panel/"+model.Version)
	request.Header.Set("Accept", "text/plain, application/json, application/octet-stream;q=0.8")
	response, err := client.Do(request)
	if err != nil {
		// url.Error includes the URL (often an access token). Never expose it.
		if errors.Is(err, errUnsafeSubscription) {
			return "", errUnsafeSubscription
		}
		return "", errors.New("订阅获取失败：请检查公网地址、DNS、TLS 及网络，或重定向和超时限制")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("订阅服务器返回 HTTP %d", response.StatusCode)
	}
	if response.ContentLength > maxRequestBytes {
		return "", errors.New("订阅内容超过 2 MiB 限制")
	}
	var reader io.Reader = response.Body
	switch strings.ToLower(strings.TrimSpace(response.Header.Get("Content-Encoding"))) {
	case "", "identity":
	case "gzip":
		decompressed, err := gzip.NewReader(response.Body)
		if err != nil {
			return "", errors.New("订阅压缩内容无效")
		}
		defer decompressed.Close()
		reader = decompressed
	default:
		return "", errors.New("订阅使用了不支持的内容编码")
	}
	content, err := io.ReadAll(io.LimitReader(reader, maxRequestBytes+1))
	if err != nil {
		return "", errors.New("订阅内容读取失败")
	}
	if len(content) > maxRequestBytes {
		return "", errors.New("订阅内容超过 2 MiB 限制")
	}
	return string(content), nil
}

func (s *Server) createSubscription(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if !readJSON(w, r, &input) {
		return
	}
	input.Name, input.URL = strings.TrimSpace(input.Name), strings.TrimSpace(input.URL)
	if !validLabel(input.Name, 120) {
		writeError(w, http.StatusBadRequest, "订阅名称须为 1–120 个字符")
		return
	}
	if _, err := validateSubscriptionURL(input.URL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	content, err := s.fetchSource(r.Context(), input.URL)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	id, err := newID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "无法生成订阅 ID")
		return
	}
	values, parseErrors := prepareImports(content, "", id, actor(r).ID)
	if len(values) == 0 {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "订阅中没有可用上游，未创建订阅", "upstreams": []model.Upstream{}, "errors": parseErrors})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.readState(w, r)
	if !ok {
		return
	}
	if len(state.Subscriptions) >= maxSubscriptions || len(state.Upstreams)+len(values) > maxUpstreams {
		writeError(w, http.StatusConflict, "订阅或上游数量超过上限")
		return
	}
	sub := model.Subscription{ID: id, OwnerID: actor(r).ID, Name: input.Name, URL: input.URL, Count: len(values), UpdatedAt: time.Now().UTC()}
	if len(parseErrors) > 0 {
		sub.LastError = fmt.Sprintf("有 %d 项未能导入", len(parseErrors))
	}
	if s.commit(w, r, store.Changes{Subscriptions: []model.Subscription{sub}, Upstreams: values}) {
		writeJSON(w, http.StatusCreated, map[string]any{"subscription": sub, "upstreams": hideOutbounds(values), "errors": parseErrors})
	}
}

func upstreamIdentity(value model.Upstream) string {
	var outbound map[string]any
	if err := json.Unmarshal(value.Outbound, &outbound); err == nil {
		delete(outbound, "tag")
		canonical, err := json.Marshal(outbound)
		if err == nil {
			hash := sha256.Sum256(canonical)
			return hex.EncodeToString(hash[:])
		}
	}
	hash := sha256.Sum256(value.Outbound)
	return hex.EncodeToString(hash[:])
}

func (s *Server) refreshSubscription(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	state, ok := s.readState(w, r)
	if !ok {
		s.mu.Unlock()
		return
	}
	sub, found := subscriptionByID(state, id)
	if !found || !actor(r).CanAccess(sub.OwnerID) {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "订阅不存在")
		return
	}
	if s.refreshing[id] {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "订阅已在刷新中")
		return
	}
	s.refreshing[id] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.refreshing, id)
		s.mu.Unlock()
	}()
	content, fetchErr := s.fetchSource(r.Context(), sub.URL)
	values, parseErrors := []model.Upstream{}, []string{}
	if fetchErr == nil {
		values, parseErrors = prepareImports(content, "", id, sub.OwnerID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok = s.readState(w, r)
	if !ok {
		return
	}
	current, found := subscriptionByID(state, id)
	if !found || !actor(r).CanAccess(current.OwnerID) || current.URL != sub.URL || current.OwnerID != sub.OwnerID {
		writeError(w, http.StatusConflict, "订阅已变更，请重新刷新")
		return
	}
	sub = current
	if fetchErr != nil {
		sub.LastError = fetchErr.Error()
		if s.commit(w, r, store.Changes{Subscriptions: []model.Subscription{sub}}) {
			writeError(w, http.StatusBadGateway, sub.LastError)
		}
		return
	}
	old := make(map[string][]model.Upstream)
	oldCount := 0
	for _, upstream := range state.Upstreams {
		if upstream.SourceID == id {
			key := upstreamIdentity(upstream)
			old[key] = append(old[key], upstream)
			oldCount++
		}
	}
	if len(parseErrors) != 0 {
		sub.LastError = fmt.Sprintf("刷新包含 %d 项解析或校验错误，保留现有上游", len(parseErrors))
		if s.commit(w, r, store.Changes{Subscriptions: []model.Subscription{sub}}) {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": sub.LastError, "preview": hideOutbounds(values), "errors": parseErrors, "replaced": false})
		}
		return
	}
	if len(state.Upstreams)-oldCount+len(values) > maxUpstreams {
		writeError(w, http.StatusConflict, "刷新将超过上游数量限制")
		return
	}
	for index := range values {
		key := upstreamIdentity(values[index])
		if matches := old[key]; len(matches) > 0 {
			values[index].ID, values[index].CreatedAt = matches[0].ID, matches[0].CreatedAt
			old[key] = matches[1:]
		}
	}
	removed := make([]string, 0)
	for _, matches := range old {
		for _, upstream := range matches {
			removed = append(removed, upstream.ID)
		}
	}
	for _, relay := range state.Relays {
		if containsID(removed, relay.UpstreamID) {
			sub.LastError = "刷新会移除仍被入口规则引用的上游；未替换，请先调整引用"
			if s.commit(w, r, store.Changes{Subscriptions: []model.Subscription{sub}}) {
				writeJSON(w, http.StatusConflict, map[string]any{"error": sub.LastError, "preview": hideOutbounds(values), "removed_ids": removed, "replaced": false})
			}
			return
		}
	}
	for _, node := range state.Nodes {
		if s.busy[node.ID] > 0 {
			writeError(w, http.StatusConflict, "节点任务正在运行，请完成后刷新订阅")
			return
		}
		applied, err := s.store.Applied(r.Context(), node.ID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusInternalServerError, "无法核对节点部署状态")
			return
		}
		for _, upstreamID := range removed {
			if applied.ReferencesUpstream(upstreamID) {
				writeError(w, http.StatusConflict, "节点当前部署或可回滚配置仍使用待移除上游，请先重新应用节点配置")
				return
			}
		}
	}
	sub.Count, sub.LastError, sub.UpdatedAt = len(values), "", time.Now().UTC()
	if s.commit(w, r, store.Changes{Upstreams: values, DeleteUpstreams: removed, Subscriptions: []model.Subscription{sub}}) {
		writeJSON(w, http.StatusOK, map[string]any{"subscription": sub, "upstreams": hideOutbounds(values), "errors": parseErrors, "removed": len(removed), "replaced": true})
	}
}

func (s *Server) deleteSubscription(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.readState(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	sub, found := subscriptionByID(state, id)
	if !found || !actor(r).CanAccess(sub.OwnerID) {
		writeError(w, http.StatusNotFound, "订阅不存在")
		return
	}
	if s.refreshing[id] {
		writeError(w, http.StatusConflict, "订阅正在刷新，请稍后删除")
		return
	}
	change := store.Changes{DeleteSubscriptions: []string{id}}
	for _, upstream := range state.Upstreams {
		if upstream.SourceID == id {
			upstream.SourceID = ""
			upstream.UpdatedAt = time.Now().UTC()
			change.Upstreams = append(change.Upstreams, upstream)
		}
	}
	if s.commit(w, r, change) {
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "kept_upstreams": len(change.Upstreams), "message": "订阅已删除；已导入上游保留并转为手动管理"})
	}
}
