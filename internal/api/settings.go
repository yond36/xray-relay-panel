package api

import (
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"xrayrelay/internal/auth"
	"xrayrelay/internal/coreversion"
	"xrayrelay/internal/model"
	"xrayrelay/internal/store"
	"xrayrelay/internal/xray"
)

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	settings, err := s.settingsFor(r.Context(), actor(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取设置失败")
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	var input model.Settings
	if !readJSON(w, r, &input) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	settings, err := s.settingsFor(r.Context(), actor(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取设置失败")
		return
	}
	if input.SubscriptionToken != "" && input.SubscriptionToken != settings.SubscriptionToken {
		writeError(w, http.StatusBadRequest, "请通过专用接口轮换订阅令牌")
		return
	}
	input.PanelURL = strings.TrimRight(strings.TrimSpace(input.PanelURL), "/")
	if input.PanelURL != "" {
		parsed, err := url.Parse(input.PanelURL)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Scheme != "http" && parsed.Scheme != "https" || len(input.PanelURL) > 2048 {
			writeError(w, http.StatusBadRequest, "面板 URL 须为有效的 HTTP/HTTPS 地址，不含账号、查询参数或片段")
			return
		}
	}
	settings.PanelURL = input.PanelURL
	settings.RegistrationOpen = input.RegistrationOpen
	if input.CoreVersion != "" {
		version, err := coreversion.Normalize(input.CoreVersion)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Xray 默认版本格式无效")
			return
		}
		settings.CoreVersion = version
	}
	// Global settings never persist an account's personal token.
	global := settings
	global.SubscriptionToken = ""
	if s.commit(w, r, store.Changes{Settings: &global}) {
		writeJSON(w, http.StatusOK, settings)
	}
}

func (s *Server) rotateToken(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, err := auth.Token()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "生成订阅令牌失败")
		return
	}
	if err := s.store.RotateSubscriptionToken(r.Context(), actor(r).ID, token); err != nil {
		writeError(w, http.StatusInternalServerError, "保存订阅令牌失败")
		return
	}
	settings, err := s.settingsFor(r.Context(), actor(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取设置失败")
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) subscriptionFeed(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !auth.ValidToken(token) {
		writeError(w, http.StatusNotFound, "订阅不存在")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	account, err := s.store.SubscriptionAccount(r.Context(), token)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "订阅不存在")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "订阅暂不可用")
		return
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(account.SubscriptionToken)) != 1 {
		writeError(w, http.StatusNotFound, "订阅不存在")
		return
	}
	state, err := s.store.State(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "订阅暂不可用")
		return
	}
	links := make([]string, 0)
	for _, relay := range state.Relays {
		if !relay.Enabled || relay.OwnerID != account.ID {
			continue
		}
		link, err := xray.ShareURL(relay)
		if err != nil {
			writeError(w, http.StatusConflict, "存在无法生成分享链接的启用规则，请检查公开地址与入口配置")
			return
		}
		links = append(links, link)
	}
	content := base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
	if len(content) > maxResponseBytes {
		writeError(w, http.StatusInternalServerError, "订阅内容超过大小限制")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `inline; filename="relay-subscription.txt"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(content))
}
