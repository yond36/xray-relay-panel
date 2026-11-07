package api

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"xrayrelay/internal/coreversion"
	"xrayrelay/internal/model"
	"xrayrelay/internal/store"
)

func validLabel(value string, maximum int) bool {
	if !utf8.ValidString(value) || strings.TrimSpace(value) == "" || utf8.RuneCountInString(value) > maximum {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func validHost(host string) bool {
	host = strings.Trim(host, "[]")
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 || strings.ContainsAny(host, "/\\:@?#% \t\r\n") {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') && !(char >= '0' && char <= '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func validFingerprint(value string) bool {
	if !strings.HasPrefix(value, "SHA256:") {
		return false
	}
	decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "SHA256:"))
	return err == nil && len(decoded) == 32
}

func normalizeNode(node *model.Node, settings model.Settings, requireTrust bool) error {
	node.Name = strings.TrimSpace(node.Name)
	node.Kind = strings.ToLower(strings.TrimSpace(node.Kind))
	if node.Kind == "" {
		node.Kind = "ssh"
	}
	if !validLabel(node.Name, 120) {
		return errors.New("节点名称须为 1–120 个字符")
	}
	if node.Kind != "ssh" && node.Kind != "local" {
		return errors.New("节点类型须为 local 或 ssh")
	}
	node.Host = strings.Trim(strings.TrimSpace(node.Host), "[]")
	node.PublicHost = strings.Trim(strings.TrimSpace(node.PublicHost), "[]")
	if node.PublicHost != "" && !validHost(node.PublicHost) {
		return errors.New("公开地址须为主机名或 IP，不含协议和端口")
	}
	if node.CoreVersion == "" {
		node.CoreVersion = settings.CoreVersion
	}
	if node.CoreVersion == "" {
		node.CoreVersion = model.DefaultCoreVersion
	}
	version, err := coreversion.Normalize(node.CoreVersion)
	if err != nil {
		return errors.New("Xray 版本格式无效")
	}
	node.CoreVersion = version
	if node.Kind == "local" {
		node.Host = "127.0.0.1"
		node.SSHPort = 0
		node.Username, node.AuthMode = "", ""
		node.Password, node.PrivateKey, node.KeyPassphrase, node.Fingerprint = "", "", "", ""
		node.HasCredentials = false
		return nil
	}
	if !validHost(node.Host) {
		return errors.New("SSH 地址须为主机名或 IP")
	}
	if node.SSHPort == 0 {
		node.SSHPort = 22
	}
	if node.SSHPort < 1 || node.SSHPort > 65535 {
		return errors.New("SSH 端口须在 1–65535 范围内")
	}
	node.Username = strings.TrimSpace(node.Username)
	if node.Username == "" {
		node.Username = "root"
	}
	if !validLabel(node.Username, 128) || strings.ContainsAny(node.Username, " \t/\\:") {
		return errors.New("SSH 用户名无效")
	}
	switch strings.ToLower(strings.TrimSpace(node.AuthMode)) {
	case "", "password":
		node.AuthMode = "password"
		if node.Password == "" {
			return errors.New("请输入 SSH 密码")
		}
	case "privatekey", "private_key", "key":
		node.AuthMode = "privatekey"
		if node.PrivateKey == "" {
			return errors.New("请输入 SSH 私钥")
		}
	default:
		return errors.New("SSH 认证方式无效")
	}
	if len(node.Password) > 4096 || len(node.PrivateKey) > 64<<10 || len(node.KeyPassphrase) > 4096 {
		return errors.New("SSH 凭据超过大小限制")
	}
	node.Fingerprint = strings.TrimSpace(node.Fingerprint)
	if node.Fingerprint != "" && !validFingerprint(node.Fingerprint) {
		return errors.New("SSH 指纹须为 SHA256 格式")
	}
	if requireTrust && node.Fingerprint == "" {
		return errors.New("请先测试节点并明确确认 SSH 主机指纹")
	}
	node.HasCredentials = true
	return nil
}

func preserveNodeCredentials(node *model.Node, old model.Node) {
	if node.Password == "" {
		node.Password = old.Password
	}
	if node.PrivateKey == "" {
		node.PrivateKey = old.PrivateKey
	}
	if node.KeyPassphrase == "" {
		node.KeyPassphrase = old.KeyPassphrase
	}
	// Trust may only carry over to the same SSH endpoint.
	if node.Fingerprint == "" && strings.EqualFold(strings.Trim(node.Host, "[]"), old.Host) && (node.SSHPort == old.SSHPort || node.SSHPort == 0 && old.SSHPort == 22) {
		node.Fingerprint = old.Fingerprint
	}
}

func duplicateNode(state model.State, node model.Node) bool {
	for _, other := range state.Nodes {
		if other.ID == node.ID {
			continue
		}
		if node.Kind == "local" && other.Kind == "local" || node.Kind == "ssh" && other.Kind == "ssh" && strings.EqualFold(node.Host, other.Host) && node.SSHPort == other.SSHPort {
			return true
		}
	}
	return false
}

func (s *Server) listNodes(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.readState(w, r)
	if !ok {
		return
	}
	state.Nodes = owned(state.Nodes, actor(r), func(v model.Node) string { return v.OwnerID })
	for index := range state.Nodes {
		state.Nodes[index] = maskNode(state.Nodes[index])
	}
	writeJSON(w, http.StatusOK, state.Nodes)
}

func (s *Server) saveNode(w http.ResponseWriter, r *http.Request) {
	var node model.Node
	if !readJSON(w, r, &node) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.readState(w, r)
	if !ok {
		return
	}
	now := time.Now().UTC()
	status := http.StatusCreated
	if id := r.PathValue("id"); id != "" {
		old, found := nodeByID(state, id)
		if !found || !actor(r).CanAccess(old.OwnerID) {
			writeError(w, http.StatusNotFound, "节点不存在")
			return
		}
		if !s.requireIdle(w, id) {
			return
		}
		if node.ID != "" && node.ID != id {
			writeError(w, http.StatusBadRequest, "节点 ID 与路径不一致")
			return
		}
		node.ID, node.OwnerID, node.CreatedAt = old.ID, old.OwnerID, old.CreatedAt
		node.AppliedRevision = old.AppliedRevision
		preserveNodeCredentials(&node, old)
		// Moving a deployed installation to another endpoint would leave an
		// unmanaged remote service. A new node must be created instead.
		if old.AppliedRevision != "" && (node.Kind != old.Kind || !strings.EqualFold(strings.Trim(node.Host, "[]"), old.Host) || node.SSHPort != old.SSHPort && !(node.SSHPort == 0 && old.SSHPort == 22)) {
			writeError(w, http.StatusConflict, "已部署节点不能更换主机或 SSH 端口，请新建节点")
			return
		}
		status = http.StatusOK
	} else {
		if len(state.Nodes) >= maxNodes {
			writeError(w, http.StatusConflict, "节点数量已达上限")
			return
		}
		id, err := newID()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "无法生成节点 ID")
			return
		}
		node.ID, node.OwnerID, node.CreatedAt, node.AppliedRevision = id, actor(r).ID, now, ""
	}
	if err := normalizeNode(&node, state.Settings, true); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if node.Kind == "local" && !actor(r).IsAdmin() {
		writeError(w, http.StatusForbidden, "本机节点仅限管理员管理")
		return
	}
	if duplicateNode(state, node) {
		writeError(w, http.StatusConflict, "相同主机与 SSH 端口已存在，请使用已有节点")
		return
	}
	for _, relay := range state.Relays {
		if relay.NodeID == node.ID && relay.Enabled && node.Kind == "ssh" && relay.Port == node.SSHPort {
			writeError(w, http.StatusConflict, "SSH 端口与启用的入口规则冲突")
			return
		}
	}
	node = markPending(node)
	if s.commit(w, r, store.Changes{Nodes: []model.Node{node}}) {
		writeJSON(w, status, maskNode(node))
	}
}

func (s *Server) deleteNode(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.readState(w, r)
	if !ok {
		return
	}
	node, found := nodeByID(state, r.PathValue("id"))
	if !found || !actor(r).CanAccess(node.OwnerID) {
		writeError(w, http.StatusNotFound, "节点不存在")
		return
	}
	if !s.requireIdle(w, node.ID) {
		return
	}
	for _, relay := range state.Relays {
		if relay.NodeID == node.ID {
			writeError(w, http.StatusConflict, "请先删除此节点的入口规则")
			return
		}
	}
	applied, err := s.store.Applied(r.Context(), node.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, "无法核对节点部署状态")
		return
	}
	if node.AppliedRevision != "" || applied.Revision != "" {
		if node.Status != "stopped" || r.URL.Query().Get("forget") != "true" {
			writeError(w, http.StatusConflict, "节点已有部署记录；请先停止服务，再使用 forget=true 明确移除管理记录，远端安装文件将保留")
			return
		}
	}
	if s.commit(w, r, store.Changes{DeleteNodes: []string{node.ID}}) {
		writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
	}
}

func (s *Server) testNode(w http.ResponseWriter, r *http.Request) {
	if s.runtime == nil {
		writeError(w, http.StatusServiceUnavailable, "节点运行时不可用")
		return
	}
	var node model.Node
	if !readJSON(w, r, &node) {
		return
	}
	s.mu.Lock()
	state, ok := s.readState(w, r)
	if !ok {
		s.mu.Unlock()
		return
	}
	if node.ID != "" {
		old, found := nodeByID(state, node.ID)
		if !found || !actor(r).CanAccess(old.OwnerID) {
			s.mu.Unlock()
			writeError(w, http.StatusNotFound, "节点不存在")
			return
		}
		if !s.requireIdle(w, node.ID) {
			s.mu.Unlock()
			return
		}
		node.OwnerID = old.OwnerID
		preserveNodeCredentials(&node, old)
	} else {
		node.OwnerID = actor(r).ID
	}
	if err := normalizeNode(&node, state.Settings, false); err != nil {
		s.mu.Unlock()
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if node.Kind == "local" && !actor(r).IsAdmin() {
		s.mu.Unlock()
		writeError(w, http.StatusForbidden, "本机节点仅限管理员操作")
		return
	}
	// Reserve the same per-node slot used by jobs; inspection also runs SSH
	// commands once trust is confirmed.
	reservation := node.ID
	for _, existing := range state.Nodes {
		if existing.Kind == node.Kind && (node.Kind == "local" || strings.EqualFold(existing.Host, node.Host) && existing.SSHPort == node.SSHPort) {
			if !actor(r).CanAccess(existing.OwnerID) {
				s.mu.Unlock()
				writeError(w, http.StatusForbidden, "此节点地址已由其他用户管理")
				return
			}
			reservation = existing.ID
			break
		}
	}
	if reservation != "" {
		if !s.requireIdle(w, reservation) {
			s.mu.Unlock()
			return
		}
		s.busy[reservation]++
		s.reserved[reservation] = true
	}
	s.mu.Unlock()
	if reservation != "" {
		defer func() {
			s.mu.Lock()
			s.busy[reservation]--
			delete(s.reserved, reservation)
			s.mu.Unlock()
		}()
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	inspection, err := s.runtime.Inspect(ctx, node)
	if err != nil {
		writeError(w, http.StatusBadGateway, safeRuntimeError(err, node, nil, nil))
		return
	}
	if node.Kind == "ssh" && node.Fingerprint == "" {
		if !validFingerprint(inspection.Fingerprint) {
			writeError(w, http.StatusBadGateway, "运行时未返回有效的 SSH 主机指纹")
			return
		}
		inspection = model.NodeInspection{Fingerprint: inspection.Fingerprint, RequiresTrust: true, Ports: []int{}, Message: "请核对 SSH 主机指纹并明确确认信任，再重新测试"}
	}
	if inspection.Ports == nil {
		inspection.Ports = []int{}
	}
	writeJSON(w, http.StatusOK, inspection)
}
