package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"xrayrelay/internal/coreversion"
	"xrayrelay/internal/model"
	"xrayrelay/internal/xray"
)

type Options struct {
	DataDir     string
	CoreVersion string
}
type Runtime struct {
	options Options
	mu      sync.Mutex
	locks   map[string]chan struct{}
}

var _ model.Runtime = (*Runtime)(nil)
var _ model.RelayDeleter = (*Runtime)(nil)

func New(o Options) *Runtime {
	if o.DataDir == "" {
		o.DataDir = "data"
	}
	if p, e := filepath.Abs(o.DataDir); e == nil {
		o.DataDir = p
	}
	if o.CoreVersion == "" {
		o.CoreVersion = model.DefaultCoreVersion
	}
	return &Runtime{options: o, locks: map[string]chan struct{}{}}
}
func (r *Runtime) lock(ctx context.Context, n model.Node) (func(), error) {
	key := n.Kind + "|" + n.Host + "|" + strconv.Itoa(n.SSHPort)
	if n.Kind == "local" {
		key = "local"
	}
	r.mu.Lock()
	ch := r.locks[key]
	if ch == nil {
		ch = make(chan struct{}, 1)
		r.locks[key] = ch
	}
	r.mu.Unlock()
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (r *Runtime) version(n model.Node) (string, error) {
	v := n.CoreVersion
	if v == "" {
		v = r.options.CoreVersion
	}
	return coreversion.Normalize(v)
}
func (r *Runtime) Inspect(ctx context.Context, n model.Node) (model.NodeInspection, error) {
	result := model.NodeInspection{Ports: []int{}}
	unlock, err := r.lock(ctx, n)
	if err != nil {
		return result, err
	}
	defer unlock()
	t, fp, err := openTarget(ctx, n, r.options.DataDir)
	if err != nil {
		var trust *trustError
		if errors.As(err, &trust) && !trust.Mismatch {
			result.Fingerprint = trust.Fingerprint
			result.RequiresTrust = true
			result.Message = "verify this SSH host fingerprint, explicitly trust it, then test again; no remote commands have run"
			return result, nil
		}
		return result, err
	}
	defer t.Close()
	reply, err := t.Call(ctx, nodeRequest{Operation: "inspect"})
	if err != nil {
		return result, err
	}
	if reply.Inspection == nil {
		return result, errors.New("node helper did not return inspection")
	}
	result = *reply.Inspection
	result.Fingerprint = fp
	if result.Ports == nil {
		result.Ports = []int{}
	}
	return result, nil
}
func (r *Runtime) Apply(ctx context.Context, n model.Node, upstreams []model.Upstream, relays []model.Relay) (model.ApplyResult, error) {
	return r.apply(ctx, n, upstreams, relays, "")
}

func (r *Runtime) DeleteRelay(ctx context.Context, n model.Node, upstreams []model.Upstream, relays []model.Relay, removedRelayID string) (model.ApplyResult, error) {
	if removedRelayID == "" {
		return model.ApplyResult{}, errors.New("removed relay id is required")
	}
	for _, relay := range relays {
		if relay.ID == removedRelayID {
			return model.ApplyResult{}, errors.New("deleted relay is still present in candidate relays")
		}
	}
	return r.apply(ctx, n, upstreams, relays, removedRelayID)
}

func (r *Runtime) apply(ctx context.Context, n model.Node, upstreams []model.Upstream, relays []model.Relay, removedRelayID string) (model.ApplyResult, error) {
	var result model.ApplyResult
	config, err := xray.Generate(n, upstreams, relays)
	if err != nil {
		return result, err
	}
	version, err := r.version(n)
	if err != nil {
		return result, err
	}
	config, err = xray.ForCoreVersion(config, version)
	if err != nil {
		return result, err
	}
	unlock, err := r.lock(ctx, n)
	if err != nil {
		return result, err
	}
	defer unlock()
	t, _, err := openTarget(ctx, n, r.options.DataDir)
	if err != nil {
		return result, err
	}
	defer t.Close()
	req := nodeRequest{Operation: "apply", Version: version, Architecture: t.Arch(), Config: config, RemovedRelayID: removedRelayID}
	cleanup, err := r.attachRelease(ctx, t, &req)
	if err != nil {
		return result, err
	}
	defer cleanup()
	reply, err := t.Call(ctx, req)
	if err != nil {
		return result, err
	}
	if reply.Apply == nil {
		return result, errors.New("node helper did not return apply result")
	}
	return *reply.Apply, nil
}
func (r *Runtime) attachRelease(ctx context.Context, t target, req *nodeRequest) (func(), error) {
	reply, err := t.Call(ctx, nodeRequest{Operation: "inspect"})
	if err != nil {
		return nil, err
	}
	if reply.Inspection != nil && reply.Inspection.CoreVersion == req.Version {
		return func() {}, nil
	}
	rel, err := downloadRelease(ctx, r.options.DataDir, req.Version, t.Arch())
	if err != nil {
		return nil, err
	}
	cleanup := func() { _ = os.RemoveAll(rel.directory) }
	path, err := t.UploadArchive(ctx, rel)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("upload official core: %w", err)
	}
	req.Archive = path
	req.SHA256 = rel.SHA256
	return cleanup, nil
}
func (r *Runtime) Probe(ctx context.Context, n model.Node, u model.Upstream) (model.ProbeResult, error) {
	result := model.ProbeResult{NodeID: n.ID, UpstreamID: u.ID, Status: "failed", CheckedAt: time.Now().UTC()}
	fail := func(err error) (model.ProbeResult, error) { result.Error = err.Error(); return result, err }
	if err := xray.ValidateUpstream(u); err != nil {
		return fail(err)
	}
	version, err := r.version(n)
	if err != nil {
		return fail(err)
	}
	unlock, err := r.lock(ctx, n)
	if err != nil {
		return fail(err)
	}
	defer unlock()
	t, _, err := openTarget(ctx, n, r.options.DataDir)
	if err != nil {
		return fail(err)
	}
	defer t.Close()
	req := nodeRequest{Operation: "probe", Version: version, Architecture: t.Arch(), Upstream: u}
	cleanup, err := r.attachRelease(ctx, t, &req)
	if err != nil {
		return fail(err)
	}
	defer cleanup()
	reply, err := t.Call(ctx, req)
	if reply.Probe != nil {
		result = *reply.Probe
		result.NodeID = n.ID
		result.UpstreamID = u.ID
	}
	if err != nil {
		return fail(err)
	}
	if reply.Probe == nil {
		return fail(errors.New("node helper did not return probe result"))
	}
	return result, nil
}
func (r *Runtime) Service(ctx context.Context, n model.Node, action string) error {
	switch action {
	case "start", "stop", "restart", "rollback":
	default:
		return errors.New("invalid service action")
	}
	unlock, err := r.lock(ctx, n)
	if err != nil {
		return err
	}
	defer unlock()
	t, _, err := openTarget(ctx, n, r.options.DataDir)
	if err != nil {
		return err
	}
	defer t.Close()
	_, err = t.Call(ctx, nodeRequest{Operation: "service", Action: action})
	return err
}
func (r *Runtime) Logs(ctx context.Context, n model.Node) (string, error) {
	unlock, err := r.lock(ctx, n)
	if err != nil {
		return "", err
	}
	defer unlock()
	t, _, err := openTarget(ctx, n, r.options.DataDir)
	if err != nil {
		return "", err
	}
	defer t.Close()
	reply, err := t.Call(ctx, nodeRequest{Operation: "logs"})
	return reply.Logs, err
}
