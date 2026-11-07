package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"xrayrelay/internal/model"
	"xrayrelay/internal/store"
	"xrayrelay/internal/xray"
)

func (s *Server) listUpstreams(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.readState(w, r)
	if !ok {
		return
	}
	state.Upstreams = owned(state.Upstreams, actor(r), func(v model.Upstream) string { return v.OwnerID })
	for index := range state.Upstreams {
		state.Upstreams[index].Outbound = nil
	}
	writeJSON(w, http.StatusOK, state.Upstreams)
}

func (s *Server) upstreamDetail(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.readState(w, r)
	if !ok {
		return
	}
	value, found := upstreamByID(state, r.PathValue("id"))
	if !found || !actor(r).CanAccess(value.OwnerID) {
		writeError(w, http.StatusNotFound, "上游不存在")
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func validateUpstream(value *model.Upstream) error {
	value.Name = strings.TrimSpace(value.Name)
	if !validLabel(value.Name, 120) {
		return errors.New("上游名称须为 1–120 个字符")
	}
	if len(value.Outbound) > 128<<10 {
		return errors.New("上游 outbound 超过大小限制")
	}
	if !json.Valid(value.Outbound) {
		return errors.New("上游 outbound 必须是有效 JSON")
	}
	return xray.ValidateUpstream(*value)
}

func affectedNodes(state model.State, upstreamID string) []model.Node {
	ids := make(map[string]bool)
	for _, relay := range state.Relays {
		if relay.UpstreamID == upstreamID {
			ids[relay.NodeID] = true
		}
	}
	values := make([]model.Node, 0, len(ids))
	for _, node := range state.Nodes {
		if ids[node.ID] {
			values = append(values, node)
		}
	}
	return values
}

func (s *Server) saveUpstream(w http.ResponseWriter, r *http.Request) {
	var upstream model.Upstream
	if !readJSON(w, r, &upstream) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.readState(w, r)
	if !ok {
		return
	}
	status := http.StatusCreated
	changes := store.Changes{}
	now := time.Now().UTC()
	if id := r.PathValue("id"); id != "" {
		old, found := upstreamByID(state, id)
		if !found || !actor(r).CanAccess(old.OwnerID) {
			writeError(w, http.StatusNotFound, "上游不存在")
			return
		}
		if upstream.ID != "" && upstream.ID != id {
			writeError(w, http.StatusBadRequest, "上游 ID 与路径不一致")
			return
		}
		for _, node := range affectedNodes(state, id) {
			if !s.requireIdle(w, node.ID) {
				return
			}
			changes.Nodes = append(changes.Nodes, markPending(node))
		}
		// Probe jobs may use an upstream that has no relay yet.
		for _, node := range state.Nodes {
			if s.busy[node.ID] != 0 {
				writeError(w, http.StatusConflict, "有节点任务正在使用上游配置，请等待任务完成后修改")
				return
			}
		}
		upstream.ID, upstream.OwnerID, upstream.CreatedAt, upstream.SourceID = id, old.OwnerID, old.CreatedAt, old.SourceID
		if upstream.Name == "" {
			upstream.Name = old.Name
		}
		if upstream.Protocol == "" {
			upstream.Protocol = old.Protocol
		}
		if upstream.Server == "" {
			upstream.Server = old.Server
		}
		if upstream.Port == 0 {
			upstream.Port = old.Port
		}
		if len(upstream.Outbound) == 0 || string(upstream.Outbound) == "null" {
			upstream.Outbound = old.Outbound
		}
		status = http.StatusOK
	} else {
		if len(state.Upstreams) >= maxUpstreams {
			writeError(w, http.StatusConflict, "上游数量已达上限")
			return
		}
		id, err := newID()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "无法生成上游 ID")
			return
		}
		upstream.ID, upstream.OwnerID, upstream.CreatedAt, upstream.SourceID = id, actor(r).ID, now, ""
	}
	upstream.UpdatedAt = now
	if err := validateUpstream(&upstream); err != nil {
		writeError(w, http.StatusBadRequest, configurationError(err))
		return
	}
	changes.Upstreams = []model.Upstream{upstream}
	if s.commit(w, r, changes) {
		upstream.Outbound = nil
		writeJSON(w, status, upstream)
	}
}

func (s *Server) deleteUpstream(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.readState(w, r)
	if !ok {
		return
	}
	upstream, found := upstreamByID(state, r.PathValue("id"))
	if !found || !actor(r).CanAccess(upstream.OwnerID) {
		writeError(w, http.StatusNotFound, "上游不存在")
		return
	}
	for _, relay := range state.Relays {
		if relay.UpstreamID == upstream.ID {
			writeError(w, http.StatusConflict, "此上游仍被入口规则引用，请先修改或删除规则")
			return
		}
	}
	for _, node := range state.Nodes {
		if s.busy[node.ID] > 0 {
			writeError(w, http.StatusConflict, "有节点任务正在运行，请等待完成后删除上游")
			return
		}
		applied, err := s.store.Applied(r.Context(), node.ID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusInternalServerError, "无法核对节点部署状态")
			return
		}
		if applied.ReferencesUpstream(upstream.ID) {
			writeError(w, http.StatusConflict, "节点当前部署或可回滚配置仍引用此上游，请先应用替代配置")
			return
		}
	}
	change := store.Changes{DeleteUpstreams: []string{upstream.ID}}
	if upstream.SourceID != "" {
		if sub, found := subscriptionByID(state, upstream.SourceID); found {
			if sub.Count > 0 {
				sub.Count--
			}
			change.Subscriptions = []model.Subscription{sub}
		}
	}
	if s.commit(w, r, change) {
		writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
	}
}

func prepareImports(content, name, sourceID, ownerID string) ([]model.Upstream, []string) {
	parsed, parseErrors := xray.ParseImports(content)
	values := make([]model.Upstream, 0)
	errors := make([]string, 0, len(parseErrors))
	// Do not echo subscription lines containing credentials in parse errors.
	for index := range parseErrors {
		errors = append(errors, fmt.Sprintf("第 %d 项解析错误，请检查格式；具体链接内容已隐藏", index+1))
	}
	if len(parsed) > 1000 {
		errors = append(errors, "单次最多导入 1000 条，超出部分未导入")
		parsed = parsed[:1000]
	}
	now := time.Now().UTC()
	for index, value := range parsed {
		if strings.TrimSpace(value.Name) == "" {
			value.Name = strings.TrimSpace(name)
			if value.Name == "" {
				value.Name = fmt.Sprintf("上游 %d", index+1)
			} else if len(parsed) > 1 {
				value.Name = fmt.Sprintf("%s %d", value.Name, index+1)
			}
		} else if len(parsed) == 1 && strings.TrimSpace(name) != "" {
			value.Name = strings.TrimSpace(name)
		}
		if err := validateUpstream(&value); err != nil {
			errors = append(errors, fmt.Sprintf("第 %d 项校验失败（%s），未导入", index+1, configurationError(err)))
			continue
		}
		id, err := newID()
		if err != nil {
			errors = append(errors, fmt.Sprintf("第 %d 项无法生成 ID，未导入", index+1))
			continue
		}
		value.ID, value.OwnerID, value.SourceID, value.CreatedAt, value.UpdatedAt = id, ownerID, sourceID, now, now
		values = append(values, value)
	}
	if len(parsed) == 0 && len(errors) == 0 {
		errors = append(errors, "内容不包含可识别的上游")
	}
	return values, errors
}

func hideOutbounds(values []model.Upstream) []model.Upstream {
	masked := append([]model.Upstream{}, values...)
	for index := range masked {
		masked[index].Outbound = nil
	}
	return masked
}

func (s *Server) importUpstreams(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Content         string `json:"content"`
		Name            string `json:"name"`
		SubscriptionURL string `json:"subscription_url"`
	}
	if !readJSON(w, r, &input) {
		return
	}
	var subscription *model.Subscription
	if strings.TrimSpace(input.SubscriptionURL) != "" {
		if strings.TrimSpace(input.Content) != "" {
			writeError(w, http.StatusBadRequest, "content 与 subscription_url 请只提供其中一个")
			return
		}
		content, err := s.fetchSource(r.Context(), input.SubscriptionURL)
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		id, err := newID()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "无法生成订阅 ID")
			return
		}
		name := strings.TrimSpace(input.Name)
		if name == "" {
			name = "导入订阅"
		}
		subscription = &model.Subscription{ID: id, OwnerID: actor(r).ID, Name: name, URL: strings.TrimSpace(input.SubscriptionURL), UpdatedAt: time.Now().UTC()}
		input.Content = content
	}
	sourceID := ""
	if subscription != nil {
		sourceID = subscription.ID
	}
	values, parseErrors := prepareImports(input.Content, input.Name, sourceID, actor(r).ID)
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.readState(w, r)
	if !ok {
		return
	}
	if len(state.Upstreams)+len(values) > maxUpstreams || subscription != nil && len(state.Subscriptions) >= maxSubscriptions {
		writeError(w, http.StatusConflict, "导入将超过上游或订阅数量限制")
		return
	}
	change := store.Changes{Upstreams: values}
	if subscription != nil {
		if !validLabel(subscription.Name, 120) {
			writeError(w, http.StatusBadRequest, "订阅名称无效")
			return
		}
		subscription.Count = len(values)
		if len(parseErrors) > 0 {
			subscription.LastError = fmt.Sprintf("有 %d 项未能导入", len(parseErrors))
		}
		change.Subscriptions = []model.Subscription{*subscription}
	}
	if s.commit(w, r, change) {
		writeJSON(w, http.StatusOK, map[string]any{"upstreams": hideOutbounds(values), "errors": parseErrors, "subscription": subscription})
	}
}

func containsID(ids []string, id string) bool {
	for _, candidate := range ids {
		if candidate == id {
			return true
		}
	}
	return false
}
