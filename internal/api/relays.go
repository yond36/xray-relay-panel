package api

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"xrayrelay/internal/model"
	"xrayrelay/internal/store"
	"xrayrelay/internal/xray"
)

func (s *Server) listRelays(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.readState(w, r)
	if ok {
		writeJSON(w, http.StatusOK, owned(state.Relays, actor(r), func(v model.Relay) string { return v.OwnerID }))
	}
}

func preserveRelaySecrets(value *model.Relay, old model.Relay) {
	if value.UUID == "" {
		value.UUID = old.UUID
	}
	if value.Password == "" {
		value.Password = old.Password
	}
	if value.RealityPrivateKey == "" {
		value.RealityPrivateKey = old.RealityPrivateKey
	}
	if value.RealityPublicKey == "" {
		value.RealityPublicKey = old.RealityPublicKey
	}
	if value.ShortID == "" {
		value.ShortID = old.ShortID
	}
	if value.Certificate == "" {
		value.Certificate = old.Certificate
	}
	if value.CertificateKey == "" {
		value.CertificateKey = old.CertificateKey
	}
}

func (s *Server) saveRelay(w http.ResponseWriter, r *http.Request) {
	var relay model.Relay
	if !readJSON(w, r, &relay) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.readState(w, r)
	if !ok {
		return
	}
	changes := store.Changes{}
	status := http.StatusCreated
	now := time.Now().UTC()
	if id := r.PathValue("id"); id != "" {
		old, found := relayByID(state, id)
		if !found || !actor(r).CanAccess(old.OwnerID) {
			writeError(w, http.StatusNotFound, "入口规则不存在")
			return
		}
		if relay.ID != "" && relay.ID != id {
			writeError(w, http.StatusBadRequest, "入口 ID 与路径不一致")
			return
		}
		if !s.requireIdle(w, old.NodeID) {
			return
		}
		if old.NodeID != relay.NodeID {
			applied, err := s.store.Applied(r.Context(), old.NodeID)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				writeError(w, http.StatusInternalServerError, "无法核对已应用规则")
				return
			}
			if applied.PendingDeleteRelayID != "" {
				writeError(w, http.StatusConflict, "原节点有尚未确认的删除部署，请先重新应用当前配置或重试删除")
				return
			}
			if applied.ReferencesRelay(old.ID) {
				writeError(w, http.StatusConflict, "移动规则前，请先在原节点禁用并应用该规则")
				return
			}
			if node, found := nodeByID(state, old.NodeID); found {
				changes.Nodes = append(changes.Nodes, markPending(node))
			}
		}
		relay.ID, relay.OwnerID, relay.CreatedAt = id, old.OwnerID, old.CreatedAt
		preserveRelaySecrets(&relay, old)
		status = http.StatusOK
	} else {
		if len(state.Relays) >= maxRelays {
			writeError(w, http.StatusConflict, "入口规则数量已达上限")
			return
		}
		id, err := newID()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "无法生成入口 ID")
			return
		}
		relay.ID, relay.OwnerID, relay.CreatedAt = id, actor(r).ID, now
	}
	node, found := nodeByID(state, relay.NodeID)
	if !found || !actor(r).CanAccess(node.OwnerID) {
		writeError(w, http.StatusNotFound, "入口引用的节点不存在")
		return
	}
	if !s.requireIdle(w, node.ID) {
		return
	}
	upstream, found := upstreamByID(state, relay.UpstreamID)
	if !found || !actor(r).CanAccess(upstream.OwnerID) {
		writeError(w, http.StatusNotFound, "入口引用的上游不存在")
		return
	}
	if node.OwnerID != relay.OwnerID || upstream.OwnerID != relay.OwnerID {
		writeError(w, http.StatusBadRequest, "入口、节点与上游须属于同一用户")
		return
	}
	relay.Name = strings.TrimSpace(relay.Name)
	if !validLabel(relay.Name, 120) {
		writeError(w, http.StatusBadRequest, "入口名称须为 1–120 个字符")
		return
	}
	if relay.Protocol == "" {
		relay.Protocol = "vless"
	}
	if relay.Network == "" {
		relay.Network = "tcp"
	}
	if relay.Security == "" {
		if relay.Protocol == "vless" {
			relay.Security = "reality"
		} else {
			relay.Security = "none"
		}
	}
	if status == http.StatusCreated && relay.Protocol == "vless" && relay.Network == "tcp" && relay.Security == "reality" && relay.Flow == "" {
		relay.Flow = "xtls-rprx-vision"
	}
	if relay.Listen == "" {
		relay.Listen = "0.0.0.0"
	}
	relay.PublicHost = strings.Trim(strings.TrimSpace(relay.PublicHost), "[]")
	if relay.PublicHost == "" {
		relay.PublicHost = node.PublicHost
		if relay.PublicHost == "" && node.Kind == "ssh" {
			relay.PublicHost = node.Host
		}
	}
	if relay.PublicHost != "" && !validHost(relay.PublicHost) {
		writeError(w, http.StatusBadRequest, "入口公开地址须为主机名或 IP")
		return
	}
	if len(relay.Certificate) > 64<<10 || len(relay.CertificateKey) > 64<<10 || len(relay.Password) > 4096 || len(relay.Path) > 2048 {
		writeError(w, http.StatusBadRequest, "入口参数超过大小限制")
		return
	}
	if err := xray.PrepareRelay(&relay); err != nil {
		writeError(w, http.StatusBadRequest, configurationError(err))
		return
	}
	if relay.Enabled {
		if node.Kind == "ssh" && relay.Port == node.SSHPort {
			writeError(w, http.StatusConflict, "入口端口不能占用 SSH 管理端口")
			return
		}
		for _, other := range state.Relays {
			if other.ID != relay.ID && other.NodeID == relay.NodeID && other.Enabled && other.Port == relay.Port {
				writeError(w, http.StatusConflict, "节点已有启用的入口使用此端口")
				return
			}
		}
	}
	relay.ShareURL = ""
	if link, err := xray.ShareURL(relay); err == nil {
		relay.ShareURL = link
	}
	relay.UpdatedAt = now
	changes.Relays = []model.Relay{relay}
	changes.Nodes = append(changes.Nodes, markPending(node))
	if s.commit(w, r, changes) {
		writeJSON(w, status, relay)
	}
}

func (s *Server) deleteRelay(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.readState(w, r)
	if !ok {
		return
	}
	relay, found := relayByID(state, r.PathValue("id"))
	if !found || !actor(r).CanAccess(relay.OwnerID) {
		writeError(w, http.StatusNotFound, "入口规则不存在")
		return
	}
	node, found := nodeByID(state, relay.NodeID)
	if !found || !actor(r).CanAccess(node.OwnerID) {
		writeError(w, http.StatusNotFound, "入口引用的节点不存在")
		return
	}
	if node.OwnerID != relay.OwnerID {
		writeError(w, http.StatusBadRequest, "入口与节点须属于同一用户")
		return
	}
	if node.Kind == "local" && !actor(r).IsAdmin() {
		writeError(w, http.StatusForbidden, "本机节点仅限管理员操作")
		return
	}
	if !s.requireIdle(w, node.ID) {
		return
	}
	applied, err := s.store.Applied(r.Context(), node.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, "无法核对已应用规则")
		return
	}
	if applied.ReferencesRelay(relay.ID) || applied.PendingDeleteRelayID != "" {
		if _, supported := s.runtime.(model.RelayDeleter); !supported {
			writeError(w, http.StatusServiceUnavailable, "节点运行时不支持安全删除已部署入口，请升级运行时后重试")
			return
		}
		if _, err := xray.Generate(node, state.Upstreams, relaysWithout(state.Relays, relay.ID)); err != nil {
			writeError(w, http.StatusBadRequest, configurationError(err))
			return
		}
		s.enqueueJob(w, r, model.Job{OwnerID: node.OwnerID, NodeID: node.ID, RelayID: relay.ID, Action: "delete-relay"})
		return
	}
	changes := store.Changes{DeleteRelays: []string{relay.ID}, Nodes: []model.Node{markPending(node)}}
	if s.commit(w, r, changes) {
		writeJSON(w, http.StatusOK, map[string]bool{"deleted": true, "pending_apply": true})
	}
}

func (s *Server) shareRelay(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.readState(w, r)
	if !ok {
		return
	}
	relay, found := relayByID(state, r.PathValue("id"))
	if !found || !actor(r).CanAccess(relay.OwnerID) {
		writeError(w, http.StatusNotFound, "入口规则不存在")
		return
	}
	link, err := xray.ShareURL(relay)
	if err != nil {
		writeError(w, http.StatusBadRequest, configurationError(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"url": link})
}
