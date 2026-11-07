package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"xrayrelay/internal/auth"
	"xrayrelay/internal/model"
	"xrayrelay/internal/store"
)

const (
	cookieName       = "relay_panel_session"
	maxRequestBytes  = 2 << 20
	maxResponseBytes = 8 << 20
	maxNodes         = 128
	maxUpstreams     = 5000
	maxRelays        = 2000
	maxSubscriptions = 128
)

type Config struct {
	DataDir       string
	Runtime       model.Runtime
	SecureCookies bool
}

type Server struct {
	store       *store.Store
	runtime     model.Runtime
	fetchSource func(context.Context, string) (string, error)
	secure      bool
	mux         *http.ServeMux
	mu          sync.Mutex
	workers     map[string]chan task
	busy        map[string]int
	refreshing  map[string]bool
	reserved    map[string]bool
	closing     bool
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	closeOnce   sync.Once
	closeErr    error
	loginLimit  auth.Limiter
	publicLimit auth.Limiter
	authSlots   chan struct{}
}

func New(config Config) (*Server, error) {
	database, err := store.Open(config.DataDir)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		store: database, runtime: config.Runtime, secure: config.SecureCookies, fetchSource: fetchSubscription,
		mux: http.NewServeMux(), workers: make(map[string]chan task), busy: make(map[string]int),
		refreshing: make(map[string]bool), reserved: make(map[string]bool), ctx: ctx, cancel: cancel, authSlots: make(chan struct{}, 4),
	}
	settings, err := database.Settings(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		settings.CoreVersion = model.DefaultCoreVersion
		err = database.Commit(ctx, store.Changes{Settings: &settings})
	}
	if err == nil {
		err = database.InterruptUnfinished(ctx)
	}
	if err != nil {
		cancel()
		database.Close()
		return nil, err
	}
	s.routes()
	return s, nil
}

func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closing = true
		s.cancel()
		s.mu.Unlock()
		s.wg.Wait()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s.closeErr = s.store.InterruptUnfinished(ctx)
		if err := s.store.Close(); s.closeErr == nil {
			s.closeErr = err
		}
	})
	return s.closeErr
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// A slow independent endpoint (such as official release discovery) must
	// never wait for the configuration mutex, including this shutdown check.
	if s.ctx.Err() != nil {
		writeError(w, http.StatusServiceUnavailable, "服务正在关闭")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		if isMutation(r.Method) && !s.sameOrigin(r) {
			writeError(w, http.StatusForbidden, "请求来源不被允许，请从面板的同一来源操作")
			return
		}
		public := r.URL.Path == "/api/bootstrap" || r.URL.Path == "/api/auth/setup" || r.URL.Path == "/api/auth/login" || r.URL.Path == "/api/auth/register"
		if !public {
			user, err := s.authenticated(r)
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, "认证存储暂不可用")
				return
			}
			if user == nil {
				writeError(w, http.StatusUnauthorized, "请先登录")
				return
			}
			r = r.WithContext(auth.WithPrincipal(r.Context(), *user))
		}
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": model.Version})
	})
	s.mux.HandleFunc("GET /api/bootstrap", s.bootstrap)
	s.mux.HandleFunc("POST /api/auth/setup", s.setup)
	s.mux.HandleFunc("POST /api/auth/login", s.login)
	s.mux.HandleFunc("POST /api/auth/register", s.register)
	s.mux.HandleFunc("GET /api/users", s.listUsers)
	s.mux.HandleFunc("POST /api/users", s.createUser)
	s.mux.HandleFunc("GET /api/core/releases", serveCoreReleases)
	s.mux.HandleFunc("POST /api/auth/logout", s.logout)
	s.mux.HandleFunc("GET /api/state", s.getState)
	s.mux.HandleFunc("GET /api/capabilities", func(w http.ResponseWriter, r *http.Request) {
		kinds := []string{"ssh"}
		if actor(r).IsAdmin() {
			kinds = []string{"local", "ssh"}
		}
		writeJSON(w, http.StatusOK, map[string]any{"runtime": s.runtime != nil, "node_kinds": kinds, "auth_modes": []string{"password", "privatekey"}, "max_request_bytes": maxRequestBytes, "subscription_refresh": "replace_source_with_reference_protection"})
	})
	s.mux.HandleFunc("POST /api/nodes/test", s.testNode)
	s.mux.HandleFunc("GET /api/nodes", s.listNodes)
	s.mux.HandleFunc("POST /api/nodes", s.saveNode)
	s.mux.HandleFunc("PUT /api/nodes/{id}", s.saveNode)
	s.mux.HandleFunc("DELETE /api/nodes/{id}", s.deleteNode)
	s.mux.HandleFunc("POST /api/nodes/{id}/apply", s.applyNode)
	s.mux.HandleFunc("POST /api/nodes/{id}/probe", s.probeNode)
	s.mux.HandleFunc("POST /api/nodes/{id}/service", s.serviceNode)
	s.mux.HandleFunc("GET /api/nodes/{id}/logs", s.nodeLogs)
	s.mux.HandleFunc("GET /api/upstreams", s.listUpstreams)
	s.mux.HandleFunc("GET /api/upstreams/{id}", s.upstreamDetail)
	s.mux.HandleFunc("POST /api/upstreams/import", s.importUpstreams)
	s.mux.HandleFunc("POST /api/upstreams", s.saveUpstream)
	s.mux.HandleFunc("PUT /api/upstreams/{id}", s.saveUpstream)
	s.mux.HandleFunc("DELETE /api/upstreams/{id}", s.deleteUpstream)
	s.mux.HandleFunc("GET /api/relays", s.listRelays)
	s.mux.HandleFunc("POST /api/relays", s.saveRelay)
	s.mux.HandleFunc("PUT /api/relays/{id}", s.saveRelay)
	s.mux.HandleFunc("DELETE /api/relays/{id}", s.deleteRelay)
	s.mux.HandleFunc("GET /api/relays/{id}/share", s.shareRelay)
	s.mux.HandleFunc("GET /api/settings", s.getSettings)
	s.mux.HandleFunc("PUT /api/settings", s.putSettings)
	s.mux.HandleFunc("POST /api/settings/rotate-token", s.rotateToken)
	s.mux.HandleFunc("POST /api/subscriptions", s.createSubscription)
	s.mux.HandleFunc("POST /api/subscriptions/{id}/refresh", s.refreshSubscription)
	s.mux.HandleFunc("DELETE /api/subscriptions/{id}", s.deleteSubscription)
	s.mux.HandleFunc("GET /sub/{token}", s.subscriptionFeed)
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "接口不存在")
	})
}

func isMutation(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func (s *Server) sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if origin == "" {
		// Browser mutations with cookies must supply a verifiable origin. A
		// cookie-free CLI may still bootstrap/login using JSON.
		_, err := r.Cookie(cookieName)
		return errors.Is(err, http.ErrNoCookie) && r.Header.Get("Sec-Fetch-Site") == ""
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.User != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	expectedScheme := "http"
	if r.TLS != nil || s.secure {
		expectedScheme = "https"
	}
	return strings.EqualFold(parsed.Scheme, expectedScheme) && equalHost(parsed.Host, r.Host, expectedScheme)
}

func equalHost(a, b, scheme string) bool {
	normalize := func(host string) string {
		parsed, err := url.Parse(scheme + "://" + host)
		if err != nil || parsed.Hostname() == "" || parsed.User != nil {
			return ""
		}
		port := parsed.Port()
		if port == "" {
			if scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		return net.JoinHostPort(strings.ToLower(parsed.Hostname()), port)
	}
	left, right := normalize(a), normalize(b)
	return left != "" && left == right
}

func (s *Server) authenticated(r *http.Request) (*model.User, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil || !auth.ValidToken(cookie.Value) {
		return nil, nil
	}
	account, err := s.store.SessionAccount(r.Context(), auth.TokenHash(cookie.Value), time.Now())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	user := account.Public()
	return &user, nil
}

func (s *Server) bootstrap(w http.ResponseWriter, r *http.Request) {
	initialized, err := s.store.Initialized(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "无法读取初始化状态")
		return
	}
	user, err := s.authenticated(r)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "认证存储暂不可用")
		return
	}
	settings, err := s.store.Settings(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "无法读取注册状态")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"initialized": initialized, "authenticated": user != nil, "registration_open": initialized && settings.RegistrationOpen, "user": user, "version": model.Version})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func remoteAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) authWork(w http.ResponseWriter, r *http.Request) bool {
	if !s.loginLimit.Allow(remoteAddress(r), time.Now()) {
		w.Header().Set("Retry-After", "300")
		writeError(w, http.StatusTooManyRequests, "登录尝试过多，请稍后再试")
		return false
	}
	select {
	case s.authSlots <- struct{}{}:
		return true
	default:
		writeError(w, http.StatusTooManyRequests, "认证请求繁忙，请稍后再试")
		return false
	}
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	var input loginRequest
	if !readJSON(w, r, &input) || !s.authWork(w, r) {
		return
	}
	defer func() { <-s.authSlots }()
	username, err := auth.CanonicalUsername(input.Username)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	input.Username = username
	// Hold this lock through hashing, singleton account creation and session
	// insertion. Setup is also protected by the SQLite primary key.
	s.mu.Lock()
	defer s.mu.Unlock()
	initialized, err := s.store.Initialized(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "无法读取初始化状态")
		return
	}
	if initialized {
		writeError(w, http.StatusConflict, "面板已经初始化")
		return
	}
	hash, err := auth.HashPassword(input.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	token, err := auth.Token()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "无法生成会话")
		return
	}
	account, err := newAccount(input.Username, hash, model.RoleAdmin)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "无法生成账户")
		return
	}
	expires := time.Now().Add(auth.SessionDuration)
	err = s.store.Setup(r.Context(), account, store.Session{AccountID: account.ID, Hash: auth.TokenHash(token), ExpiresAt: expires})
	if errors.Is(err, store.ErrInitialized) {
		writeError(w, http.StatusConflict, "面板已经初始化")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "保存初始账户失败")
		return
	}
	s.setCookie(w, token, expires)
	s.loginLimit.Reset(remoteAddress(r))
	writeJSON(w, http.StatusCreated, map[string]any{"authenticated": true, "user": account.Public()})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var input loginRequest
	if !readJSON(w, r, &input) || !s.authWork(w, r) {
		return
	}
	defer func() { <-s.authSlots }()
	account, err := s.store.AccountByUsername(r.Context(), input.Username)
	if errors.Is(err, sql.ErrNoRows) {
		initialized, initErr := s.store.Initialized(r.Context())
		if initErr != nil {
			writeError(w, http.StatusServiceUnavailable, "认证存储暂不可用")
		} else if !initialized {
			writeError(w, http.StatusConflict, "请先初始化面板")
		} else {
			writeError(w, http.StatusUnauthorized, "用户名或密码错误")
		}
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "认证存储暂不可用")
		return
	}
	if !auth.VerifyPassword(account.Hash, input.Password) {
		writeError(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	token, err := auth.Token()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "无法生成会话")
		return
	}
	expires := time.Now().Add(auth.SessionDuration)
	if err := s.store.AddSession(r.Context(), store.Session{AccountID: account.ID, Hash: auth.TokenHash(token), ExpiresAt: expires}); err != nil {
		writeError(w, http.StatusInternalServerError, "无法保存会话")
		return
	}
	s.setCookie(w, token, expires)
	s.loginLimit.Reset(remoteAddress(r))
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": account.Public()})
}

func (s *Server) setCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/", HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: int(auth.SessionDuration.Seconds())})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(cookieName); err == nil {
		if err := s.store.DeleteSession(r.Context(), auth.TokenHash(cookie.Value)); err != nil {
			writeError(w, http.StatusInternalServerError, "注销会话失败")
			return
		}
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", Value: "", HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)})
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
}

func (s *Server) getState(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.readState(w, r)
	if !ok {
		return
	}
	state, err := s.visibleState(r.Context(), actor(r), state)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取账户信息失败")
		return
	}
	maskState(&state)
	writeJSON(w, http.StatusOK, state)
}

func maskNode(node model.Node) model.Node {
	node.HasCredentials = node.Password != "" || node.PrivateKey != ""
	node.Password, node.PrivateKey, node.KeyPassphrase = "", "", ""
	return node
}

func maskState(state *model.State) {
	for index := range state.Nodes {
		state.Nodes[index] = maskNode(state.Nodes[index])
	}
	for index := range state.Upstreams {
		state.Upstreams[index].Outbound = nil
	}
}

func readJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "请求须使用 application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "请求内容超过大小限制")
		} else {
			writeError(w, http.StatusBadRequest, "JSON 请求格式或字段无效")
		}
		return false
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "请求只能包含一个 JSON 对象")
		return false
	}
	return true
}

func writeError(w http.ResponseWriter, status int, message string) {
	if len(message) > 2048 {
		message = message[:2048]
	}
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	var buffer bytes.Buffer
	if err := json.NewEncoder(&buffer).Encode(value); err != nil || buffer.Len() > maxResponseBytes {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "{\"error\":\"响应超过限制或无法编码，请缩小数据范围\"}\n")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buffer.Bytes())
}

func newID() (string, error) { return auth.Token() }

func (s *Server) readState(w http.ResponseWriter, r *http.Request) (model.State, bool) {
	state, err := s.store.State(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取面板数据失败")
		return state, false
	}
	return state, true
}

func (s *Server) commit(w http.ResponseWriter, r *http.Request, change store.Changes) bool {
	if err := s.store.Commit(r.Context(), change); err != nil {
		writeError(w, http.StatusInternalServerError, "数据保存失败")
		return false
	}
	return true
}

func nodeByID(state model.State, id string) (model.Node, bool) {
	for _, node := range state.Nodes {
		if node.ID == id {
			return node, true
		}
	}
	return model.Node{}, false
}

func upstreamByID(state model.State, id string) (model.Upstream, bool) {
	for _, upstream := range state.Upstreams {
		if upstream.ID == id {
			return upstream, true
		}
	}
	return model.Upstream{}, false
}

func relayByID(state model.State, id string) (model.Relay, bool) {
	for _, relay := range state.Relays {
		if relay.ID == id {
			return relay, true
		}
	}
	return model.Relay{}, false
}

func subscriptionByID(state model.State, id string) (model.Subscription, bool) {
	for _, subscription := range state.Subscriptions {
		if subscription.ID == id {
			return subscription, true
		}
	}
	return model.Subscription{}, false
}

func (s *Server) requireIdle(w http.ResponseWriter, nodeID string) bool {
	if s.busy[nodeID] > 0 {
		writeError(w, http.StatusConflict, "节点有排队或运行中的任务，请等待任务完成后修改")
		return false
	}
	return true
}

func markPending(node model.Node) model.Node {
	node.Status = "pending"
	node.LastError = ""
	node.UpdatedAt = time.Now().UTC()
	return node
}

func configurationError(err error) string {
	// Parser/generator validation errors may describe fields, but must not
	// reflect an arbitrarily long import or an entire outbound object.
	message := strings.TrimSpace(err.Error())
	if len(message) > 512 {
		message = message[:512] + "…"
	}
	return fmt.Sprintf("配置无效：%s", message)
}
