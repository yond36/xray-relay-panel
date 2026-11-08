package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"xrayrelay/internal/model"
	"xrayrelay/internal/store"
	"xrayrelay/internal/xray"
)

type task struct {
	job model.Job
}

func (s *Server) applyNode(w http.ResponseWriter, r *http.Request) {
	s.enqueue(w, r, "apply", "")
}

func (s *Server) probeNode(w http.ResponseWriter, r *http.Request) {
	var input struct {
		UpstreamID string `json:"upstream_id"`
	}
	if readJSON(w, r, &input) {
		s.enqueue(w, r, "probe", input.UpstreamID)
	}
}

func (s *Server) serviceNode(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Action string `json:"action"`
	}
	if !readJSON(w, r, &input) {
		return
	}
	switch input.Action {
	case "start", "stop", "restart", "rollback":
		s.enqueue(w, r, input.Action, "")
	default:
		writeError(w, http.StatusBadRequest, "服务操作须为 start、stop、restart 或 rollback")
	}
}

func (s *Server) enqueue(w http.ResponseWriter, r *http.Request, action, upstreamID string) {
	if s.runtime == nil {
		writeError(w, http.StatusServiceUnavailable, "节点运行时不可用")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		writeError(w, http.StatusServiceUnavailable, "服务正在关闭")
		return
	}
	state, ok := s.readState(w, r)
	if !ok {
		return
	}
	node, found := nodeByID(state, r.PathValue("id"))
	if !found || !actor(r).CanAccess(node.OwnerID) {
		writeError(w, http.StatusNotFound, "节点不存在")
		return
	}
	if s.reserved[node.ID] {
		writeError(w, http.StatusConflict, "节点正在检查或读取日志，请稍后重试")
		return
	}
	if s.busy[node.ID] >= 16 {
		writeError(w, http.StatusTooManyRequests, "此节点待执行任务过多")
		return
	}
	if node.Kind == "local" && !actor(r).IsAdmin() {
		writeError(w, http.StatusForbidden, "本机节点仅限管理员操作")
		return
	}
	if action == "probe" {
		upstream, found := upstreamByID(state, upstreamID)
		if !found || !actor(r).CanAccess(upstream.OwnerID) {
			writeError(w, http.StatusNotFound, "上游不存在")
			return
		}
		if upstream.OwnerID != node.OwnerID {
			writeError(w, http.StatusBadRequest, "节点与探测上游须属于同一用户")
			return
		}
	}
	if action == "apply" {
		if _, err := xray.Generate(node, state.Upstreams, state.Relays); err != nil {
			writeError(w, http.StatusBadRequest, configurationError(err))
			return
		}
	}
	if action == "rollback" {
		applied, err := s.store.Applied(r.Context(), node.ID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusInternalServerError, "无法读取回滚记录")
			return
		}
		if err := validateRollback(state, applied, node.ID); err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
	}
	job := model.Job{OwnerID: node.OwnerID, NodeID: node.ID, Action: action}
	if action == "probe" {
		job.UpstreamID = upstreamID
	}
	s.enqueueJob(w, r, job)
}

// enqueueJob requires s.mu and all action-specific permission and busy checks.
func (s *Server) enqueueJob(w http.ResponseWriter, r *http.Request, job model.Job) {
	if s.runtime == nil {
		writeError(w, http.StatusServiceUnavailable, "节点运行时不可用")
		return
	}
	if s.closing {
		writeError(w, http.StatusServiceUnavailable, "服务正在关闭")
		return
	}
	id, err := newID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "无法生成任务 ID")
		return
	}
	job.ID, job.Status, job.Message, job.CreatedAt = id, "queued", "等待节点任务执行", time.Now().UTC()
	if !s.commit(w, r, store.Changes{Jobs: []model.Job{job}}) {
		return
	}
	queue, exists := s.workers[job.NodeID]
	if !exists {
		queue = make(chan task, 16)
		s.workers[job.NodeID] = queue
		s.wg.Add(1)
		go s.worker(queue)
	}
	s.busy[job.NodeID]++
	queue <- task{job: job}
	writeJSON(w, http.StatusAccepted, job)
}

func validateRollback(state model.State, applied store.Applied, nodeID string) error {
	if applied.PendingDeleteRelayID != "" {
		return errors.New("节点有尚未确认的删除部署，请重新应用当前配置或重试删除后再回滚")
	}
	if applied.Previous == nil {
		return errors.New("没有可确认的上次成功部署，无法回滚")
	}
	if !rollbackReferencesPresent(state, *applied.Previous, nodeID) {
		return errors.New("上次部署引用的规则或上游已被删除或移动，请重新应用当前配置")
	}
	return nil
}

func relaysWithout(relays []model.Relay, id string) []model.Relay {
	values := make([]model.Relay, 0, len(relays))
	for _, relay := range relays {
		if relay.ID != id {
			values = append(values, relay)
		}
	}
	return values
}

func rollbackReferencesPresent(state model.State, snapshot store.Applied, nodeID string) bool {
	for _, id := range snapshot.RelayIDs {
		relay, found := relayByID(state, id)
		if !found || relay.NodeID != nodeID {
			return false
		}
	}
	for _, id := range snapshot.UpstreamIDs {
		if _, found := upstreamByID(state, id); !found {
			return false
		}
	}
	return true
}

func (s *Server) worker(queue <-chan task) {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case work := <-queue:
			if s.ctx.Err() != nil {
				return
			}
			s.execute(work)
		}
	}
}

func (s *Server) execute(work task) {
	defer func() {
		s.mu.Lock()
		s.busy[work.job.NodeID]--
		s.mu.Unlock()
	}()
	var node model.Node
	var state model.State
	var executionErr error
	var result model.ApplyResult
	var probe *model.ProbeResult
	var prior store.Applied
	// Convert a runtime panic into a durable failed task without losing the
	// node worker and every task queued behind it.
	defer func() {
		if recovered := recover(); recovered != nil {
			s.finishTask(work, node, state, prior, result, probe, errors.New("节点运行时意外终止，远端状态未知"))
		}
	}()
	s.mu.Lock()
	state, executionErr = s.store.State(s.ctx)
	if executionErr == nil {
		var found bool
		node, found = nodeByID(state, work.job.NodeID)
		if !found {
			executionErr = errors.New("任务引用的节点不存在")
		}
	}
	if executionErr == nil {
		prior, executionErr = s.store.Applied(s.ctx, node.ID)
		if errors.Is(executionErr, sql.ErrNoRows) {
			executionErr = nil
		}
	}
	if executionErr == nil && work.job.Action == "rollback" {
		// The preceding task can replace or invalidate Previous after enqueue.
		executionErr = validateRollback(state, prior, node.ID)
	}
	if executionErr == nil && work.job.Action == "delete-relay" {
		relay, found := relayByID(state, work.job.RelayID)
		if !found || relay.NodeID != node.ID || relay.OwnerID != node.OwnerID || work.job.OwnerID != node.OwnerID {
			executionErr = errors.New("待删除的入口规则不存在或已不属于此节点")
		} else if _, supported := s.runtime.(model.RelayDeleter); !supported {
			executionErr = errors.New("节点运行时不支持安全删除已部署入口，请升级运行时后重试")
		} else {
			_, executionErr = xray.Generate(node, state.Upstreams, relaysWithout(state.Relays, relay.ID))
		}
	}
	if executionErr == nil {
		work.job.Status, work.job.Message = "running", "正在节点上执行"
		changes := store.Changes{Jobs: []model.Job{work.job}}
		if work.job.Action == "delete-relay" {
			// Keep the last confirmed snapshots, but block rollback before any
			// remote side effect. Only a committed apply/delete clears intent.
			intent := prior
			intent.PendingDeleteRelayID = work.job.RelayID
			changes.Applied = map[string]store.Applied{node.ID: intent}
		}
		executionErr = s.store.Commit(s.ctx, changes)
	}
	s.mu.Unlock()
	if executionErr != nil {
		s.finishTask(work, node, state, prior, result, probe, executionErr)
		return
	}
	timeout := 2 * time.Minute
	if work.job.Action == "apply" || work.job.Action == "delete-relay" {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(s.ctx, timeout)
	defer cancel()
	switch work.job.Action {
	case "apply", "delete-relay":
		if work.job.Action == "delete-relay" {
			result, executionErr = s.runtime.(model.RelayDeleter).DeleteRelay(ctx, node, state.Upstreams, relaysWithout(state.Relays, work.job.RelayID), work.job.RelayID)
		} else {
			result, executionErr = s.runtime.Apply(ctx, node, state.Upstreams, state.Relays)
		}
		if executionErr == nil && strings.TrimSpace(result.Revision) == "" {
			executionErr = errors.New("运行时未返回成功部署的 revision，远端状态需核对")
		}
	case "probe":
		upstream, found := upstreamByID(state, work.job.UpstreamID)
		if !found {
			executionErr = errors.New("探测上游已不存在")
			break
		}
		value, err := s.runtime.Probe(ctx, node, upstream)
		executionErr = err
		probe = &value
		probe.OwnerID, probe.NodeID, probe.UpstreamID = node.OwnerID, node.ID, upstream.ID
		probe.ID, err = newID()
		if err != nil && executionErr == nil {
			executionErr = err
		}
		probe.CheckedAt = time.Now().UTC()
		if executionErr == nil {
			switch strings.ToLower(probe.Status) {
			case "ok", "success", "succeeded", "healthy", "partial":
				if net.ParseIP(probe.IPv4) == nil && net.ParseIP(probe.IPv6) == nil {
					executionErr = errors.New("探测未获得有效的出口 IP")
				}
			default:
				executionErr = errors.New("探测未成功")
				if probe.Error != "" {
					executionErr = errors.New(probe.Error)
				}
			}
		}
	default:
		executionErr = s.runtime.Service(ctx, node, work.job.Action)
	}
	if executionErr == nil && ctx.Err() != nil {
		executionErr = ctx.Err()
	}
	s.finishTask(work, node, state, prior, result, probe, executionErr)
}

func deploymentSnapshot(nodeID, revision string, relays []model.Relay) store.Applied {
	value := store.Applied{Revision: revision, RelayIDs: []string{}, UpstreamIDs: []string{}}
	for _, relay := range relays {
		if relay.NodeID != nodeID || !relay.Enabled {
			continue
		}
		value.RelayIDs = append(value.RelayIDs, relay.ID)
		if !containsID(value.UpstreamIDs, relay.UpstreamID) {
			value.UpstreamIDs = append(value.UpstreamIDs, relay.UpstreamID)
		}
	}
	return value
}

func desiredConfigHash(node model.Node, state model.State) string {
	relays := make([]model.Relay, 0)
	used := make(map[string]bool)
	for _, relay := range state.Relays {
		if relay.NodeID == node.ID && relay.Enabled {
			relay.OwnerID, relay.Name, relay.ShareURL = "", "", ""
			relay.CreatedAt, relay.UpdatedAt = time.Time{}, time.Time{}
			relays = append(relays, relay)
			used[relay.UpstreamID] = true
		}
	}
	sort.Slice(relays, func(i, j int) bool { return relays[i].ID < relays[j].ID })
	upstreams := make([]model.Upstream, 0)
	for _, upstream := range state.Upstreams {
		if used[upstream.ID] {
			upstream.OwnerID, upstream.Name, upstream.SourceID, upstream.Server, upstream.Protocol = "", "", "", "", ""
			upstream.Port = 0
			upstream.CreatedAt, upstream.UpdatedAt = time.Time{}, time.Time{}
			upstreams = append(upstreams, upstream)
		}
	}
	sort.Slice(upstreams, func(i, j int) bool { return upstreams[i].ID < upstreams[j].ID })
	data, _ := json.Marshal(struct {
		Version   string           `json:"version"`
		Relays    []model.Relay    `json:"relays"`
		Upstreams []model.Upstream `json:"upstreams"`
	}{node.CoreVersion, relays, upstreams})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func (s *Server) finishTask(work task, node model.Node, state model.State, prior store.Applied, result model.ApplyResult, probe *model.ProbeResult, executionErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	job := work.job
	job.FinishedAt = &now
	job.Status, job.Message = "succeeded", "任务执行成功"
	changes := store.Changes{}
	originalNode := node
	if executionErr != nil {
		job.Status = "failed"
		if s.ctx.Err() != nil {
			job.Status = "interrupted"
		}
		job.Error = safeRuntimeError(executionErr, node, state.Upstreams, state.Relays)
		job.Message = "任务未成功：" + job.Error
		if node.ID != "" && job.Action != "probe" {
			node.Status, node.LastError = "error", job.Error
			if job.Status == "interrupted" {
				node.Status = "interrupted"
			}
		}
	} else {
		switch job.Action {
		case "apply", "delete-relay":
			job.Revision, job.Message = result.Revision, "配置已在节点应用并确认成功"
			node.AppliedRevision, node.Status, node.LastError = result.Revision, "ready", ""
			if result.CoreVersion != "" {
				node.CoreVersion = result.CoreVersion
			}
			deployed := state
			if job.Action == "delete-relay" {
				deployed.Relays = relaysWithout(state.Relays, job.RelayID)
				changes.DeleteRelays = []string{job.RelayID}
				job.Message = "入口规则已从节点配置移除并删除"
			}
			snapshot := deploymentSnapshot(node.ID, result.Revision, deployed.Relays)
			snapshot.ConfigHash = desiredConfigHash(node, deployed)
			// An unresolved remote deletion makes the old current untrustworthy.
			// Otherwise keep only that current, never its older Previous, and
			// only when it cannot resurrect the relay being deleted.
			if prior.Revision != "" && prior.PendingDeleteRelayID == "" {
				previous := prior
				previous.Previous = nil
				if job.Action != "delete-relay" || !previous.ReferencesRelay(job.RelayID) {
					snapshot.Previous = &previous
				}
			}
			changes.Applied = map[string]store.Applied{node.ID: snapshot}
		case "stop":
			node.Status, node.LastError = "stopped", ""
		case "start", "restart":
			node.Status = "pending"
			if prior.PendingDeleteRelayID == "" && prior.ConfigHash != "" && prior.ConfigHash == desiredConfigHash(node, state) {
				node.Status = "ready"
			}
			node.LastError = ""
		case "rollback":
			if prior.Previous == nil {
				job.Status, job.Error, job.Message = "failed", "回滚部署记录丢失，远端状态未知", "回滚部署记录丢失，远端状态未知"
				node.Status, node.LastError = "error", job.Error
			} else {
				snapshot := *prior.Previous
				prior.Previous = nil
				snapshot.Previous = &prior
				changes.Applied = map[string]store.Applied{node.ID: snapshot}
				node.AppliedRevision, node.Status, node.LastError = snapshot.Revision, "pending", ""
				job.Revision, job.Message = snapshot.Revision, "已回滚；面板当前期望配置仍待显式应用"
			}
		}
	}
	if probe != nil {
		probe.JobID = job.ID
		if executionErr != nil {
			probe.Status, probe.Error = "failed", job.Error
		} else if probe.Status != "partial" {
			probe.Status = "ok"
		}
		probe.Error = safeRuntimeText(probe.Error, node, state.Upstreams, state.Relays)
		probe.IPv6Error = safeRuntimeText(probe.IPv6Error, node, state.Upstreams, state.Relays)
		if probe.ID != "" {
			changes.Probes = []model.ProbeResult{*probe}
		}
	}
	if node.ID != "" {
		node.UpdatedAt = now
		changes.Nodes = []model.Node{node}
	}
	changes.Jobs = []model.Job{job}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.store.Commit(ctx, changes); err != nil {
		// A successful remote action with a failed local commit is explicitly
		// recorded as unknown/failed, never reported as successful.
		job.Status, job.Error, job.Message = "failed", "无法持久化执行结果，远端状态未知，请核对节点后重新执行", "无法持久化执行结果，远端状态未知，请核对节点后重新执行"
		job.Revision = ""
		fallback := store.Changes{Jobs: []model.Job{job}}
		if originalNode.ID != "" {
			originalNode.Status, originalNode.LastError, originalNode.UpdatedAt = "error", job.Error, now
			fallback.Nodes = []model.Node{originalNode}
		}
		// Preserve the last confirmed revision and any durable deletion intent;
		// no part of the successful result may escape the failed transaction.
		_ = s.store.Commit(ctx, fallback)
	}
}

func safeRuntimeError(err error, node model.Node, upstreams []model.Upstream, relays []model.Relay) string {
	if err == nil {
		return ""
	}
	return safeRuntimeText(err.Error(), node, upstreams, relays)
}

func safeRuntimeText(message string, node model.Node, upstreams []model.Upstream, relays []model.Relay) string {
	secrets := []string{node.Password, node.PrivateKey, node.KeyPassphrase}
	for _, upstream := range upstreams {
		secrets = append(secrets, string(upstream.Outbound))
	}
	for _, relay := range relays {
		secrets = append(secrets, relay.Password, relay.RealityPrivateKey, relay.CertificateKey)
	}
	for _, secret := range secrets {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[已隐藏]")
		}
	}
	message = strings.ReplaceAll(message, "\x00", "")
	if len(message) > 4096 {
		message = message[:4096] + "…"
	}
	return message
}

func (s *Server) nodeLogs(w http.ResponseWriter, r *http.Request) {
	if s.runtime == nil {
		writeError(w, http.StatusServiceUnavailable, "节点运行时不可用")
		return
	}
	s.mu.Lock()
	state, ok := s.readState(w, r)
	if !ok {
		s.mu.Unlock()
		return
	}
	node, found := nodeByID(state, r.PathValue("id"))
	if !found || !actor(r).CanAccess(node.OwnerID) {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "节点不存在")
		return
	}
	if !s.requireIdle(w, node.ID) {
		s.mu.Unlock()
		return
	}
	s.busy[node.ID]++
	s.reserved[node.ID] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.busy[node.ID]--
		delete(s.reserved, node.ID)
		s.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	logs, err := s.runtime.Logs(ctx, node)
	if err != nil {
		writeError(w, http.StatusBadGateway, safeRuntimeError(err, node, state.Upstreams, state.Relays))
		return
	}
	logs = safeRuntimeTextUnbounded(logs, node, state.Upstreams, state.Relays)
	truncated := len(logs) > 256<<10
	if truncated {
		logs = "[日志已截断，仅显示末尾 256 KiB]\n" + logs[len(logs)-(256<<10):]
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": logs, "truncated": truncated})
}

func safeRuntimeTextUnbounded(message string, node model.Node, upstreams []model.Upstream, relays []model.Relay) string {
	// Redact each line without shrinking legitimate multi-line logs to the
	// error-message limit. Bound the input before allocating replacements.
	if len(message) > 512<<10 {
		message = message[len(message)-(512<<10):]
	}
	lines := strings.Split(message, "\n")
	for index := range lines {
		lines[index] = safeRuntimeText(lines[index], node, upstreams, relays)
	}
	return strings.Join(lines, "\n")
}
