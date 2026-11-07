package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"xrayrelay/internal/auth"
	"xrayrelay/internal/model"
	"xrayrelay/internal/store"
)

func actor(r *http.Request) model.User {
	user, _ := auth.Principal(r.Context())
	return user
}

func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !actor(r).IsAdmin() {
		writeError(w, http.StatusForbidden, "此操作仅限管理员")
		return false
	}
	return true
}

func owned[T any](values []T, user model.User, owner func(T) string) []T {
	result := make([]T, 0, len(values))
	for _, value := range values {
		if user.CanAccess(owner(value)) {
			result = append(result, value)
		}
	}
	return result
}

// Only HTTP responses use this view. Validation, reference protection and node
// workers must always operate on the full persistent state.
func (s *Server) visibleState(ctx context.Context, user model.User, state model.State) (model.State, error) {
	state.Nodes = owned(state.Nodes, user, func(v model.Node) string { return v.OwnerID })
	state.Upstreams = owned(state.Upstreams, user, func(v model.Upstream) string { return v.OwnerID })
	state.Relays = owned(state.Relays, user, func(v model.Relay) string { return v.OwnerID })
	state.Subscriptions = owned(state.Subscriptions, user, func(v model.Subscription) string { return v.OwnerID })
	state.Jobs = owned(state.Jobs, user, func(v model.Job) string { return v.OwnerID })
	state.Probes = owned(state.Probes, user, func(v model.ProbeResult) string { return v.OwnerID })
	state.CurrentUser = &user
	state.Users = []model.User{user}
	var err error
	if user.IsAdmin() {
		state.Users, err = s.store.Users(ctx)
		if err != nil {
			return state, err
		}
	}
	state.Settings, err = s.settingsFor(ctx, user)
	return state, err
}

func (s *Server) settingsFor(ctx context.Context, user model.User) (model.Settings, error) {
	settings, err := s.store.Settings(ctx)
	if err != nil {
		return model.Settings{}, err
	}
	account, err := s.store.AccountByID(ctx, user.ID)
	if err != nil {
		return model.Settings{}, err
	}
	settings.SubscriptionToken = account.SubscriptionToken
	return settings, nil
}

func newAccount(username, hash, role string) (store.Account, error) {
	id, err := newID()
	if err != nil {
		return store.Account{}, err
	}
	token, err := auth.Token()
	return store.Account{ID: id, Username: username, Hash: hash, Role: role, SubscriptionToken: token}, err
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	// This exact two-field request rejects role/owner injection.
	var input loginRequest
	if !readJSON(w, r, &input) {
		return
	}
	initialized, err := s.store.Initialized(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "认证存储暂不可用")
		return
	}
	if !initialized {
		writeError(w, http.StatusConflict, "请先初始化面板")
		return
	}
	settings, err := s.store.Settings(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "无法读取注册状态")
		return
	}
	if !settings.RegistrationOpen {
		writeError(w, http.StatusForbidden, "管理员已关闭注册")
		return
	}
	if !s.authWork(w, r) {
		return
	}
	defer func() { <-s.authSlots }()
	account, ok := s.prepareNewAccount(w, input.Username, input.Password, model.RoleUser)
	if !ok {
		return
	}
	token, err := auth.Token()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "无法生成会话")
		return
	}
	expires := time.Now().Add(auth.SessionDuration)
	session := store.Session{AccountID: account.ID, Hash: auth.TokenHash(token), ExpiresAt: expires}
	if err := s.store.CreateAccount(r.Context(), account, &session, true); err != nil {
		writeAccountError(w, err)
		return
	}
	s.setCookie(w, token, expires)
	s.loginLimit.Reset(remoteAddress(r))
	writeJSON(w, http.StatusCreated, map[string]any{"authenticated": true, "user": account.Public()})
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	users, err := s.store.Users(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取用户列表失败")
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !readJSON(w, r, &input) {
		return
	}
	if input.Role == "" {
		input.Role = model.RoleUser
	}
	if input.Role != model.RoleAdmin && input.Role != model.RoleUser {
		writeError(w, http.StatusBadRequest, "角色须为 admin 或 user")
		return
	}
	if !s.authWork(w, r) {
		return
	}
	defer func() { <-s.authSlots }()
	account, ok := s.prepareNewAccount(w, input.Username, input.Password, input.Role)
	if !ok {
		return
	}
	if err := s.store.CreateAccount(r.Context(), account, nil, false); err != nil {
		writeAccountError(w, err)
		return
	}
	s.loginLimit.Reset(remoteAddress(r))
	writeJSON(w, http.StatusCreated, account.Public())
}

func (s *Server) prepareNewAccount(w http.ResponseWriter, username, password, role string) (store.Account, bool) {
	name, err := auth.CanonicalUsername(username)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return store.Account{}, false
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return store.Account{}, false
	}
	account, err := newAccount(name, hash, role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "无法生成账户")
		return store.Account{}, false
	}
	return account, true
}

func writeAccountError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrUsernameTaken):
		writeError(w, http.StatusConflict, "用户名已存在")
	case errors.Is(err, store.ErrRegistrationClosed):
		writeError(w, http.StatusForbidden, "管理员已关闭注册")
	case errors.Is(err, store.ErrNotInitialized):
		writeError(w, http.StatusConflict, "请先初始化面板")
	default:
		writeError(w, http.StatusInternalServerError, "保存账户失败")
	}
}
