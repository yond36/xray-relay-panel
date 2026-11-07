# Implementation contract

All JSON uses snake_case. Shared structs and Runtime interface live in internal/model/model.go. Do not edit these without coordination. Production is Linux amd64/arm64 with systemd; Windows is development. Protect existing Xray: our ONLY unit is xray-relay-panel-node.service; use /opt/xray-relay-panel-node and /var/lib/xray-relay-panel-node. Never run killall/pkill xray, modify /etc/xray or /usr/local/etc/xray, change global sysctl/firewall, or invoke 233boy scripts. Test on supplied machine only with separate free ports.

API contract (same origin):
- GET /api/bootstrap => {initialized:boolean, authenticated:boolean, version:string}
- POST /api/auth/setup or /api/auth/login {username,password}; POST /api/auth/logout
- GET /api/state => model.State (empty slices serialize as [], not null). GET /api/capabilities optional.
- POST /api/nodes/test body Node => NodeInspection (requires_trust returns observed fingerprint, without running commands).
- POST /api/nodes, PUT /api/nodes/{id}, DELETE /api/nodes/{id}
- POST /api/nodes/{id}/apply => Job (202). POST /api/nodes/{id}/probe {upstream_id} => Job (202).
- POST /api/nodes/{id}/service {action:start|stop|restart|rollback} => Job. GET /api/nodes/{id}/logs => {logs:string}
- POST /api/upstreams/import {content:string, name?:string} => {upstreams:Upstream[], errors:string[]}; optional subscription_url supplied separately.
- POST /api/upstreams accepts validated Upstream with outbound JSON; PUT/DELETE /api/upstreams/{id}
- POST/PUT/DELETE /api/relays/{id?}. Backend calls xray.PrepareRelay(&relay) before saving. Validates all references and per-node port conflicts. Saving does not apply; UI explicitly applies node config. Deletes do not silently leave applied node configuration.
- GET /api/relays/{id}/share => {url:string}; QR generated locally by frontend.
- GET/PUT /api/settings; POST /api/settings/rotate-token
- POST /api/subscriptions {name,url}, POST /api/subscriptions/{id}/refresh, DELETE /api/subscriptions/{id}
- GET /sub/{token} => Base64 URI list. Tokens generated randomly.
- GET /healthz => {status:"ok", version:string}
Errors: {error:string}. Sessions in HttpOnly SameSite cookies. API protected except bootstrap/auth; reject cross-origin mutations. Server masks node secrets in responses; empty update values preserve credentials. Upstream outbound secrets omitted from list/state; explicit authenticated detail endpoint may return on user request. Relay share data is sensitive but must be available to authenticated owner for QR/export.

Required Go signatures:
- internal/api: type Config struct {DataDir string; Runtime model.Runtime; SecureCookies bool}; func New(Config) (*Server,error); Server implements http.Handler and Close() error.
- internal/xray: func ParseImports(content string) ([]model.Upstream, []string); func ValidateUpstream(model.Upstream) error; func PrepareRelay(*model.Relay) error; func ShareURL(model.Relay) (string,error); func Generate(model.Node, []model.Upstream, []model.Relay) ([]byte,error). Generator includes default blackhole and only enabled business inbounds. Runtime Probe uses a separate ephemeral authenticated loopback-only process with the exact same upstream outbound, then cleans it up; no permanent probe ports are allocated.
- internal/engine: type Options struct {DataDir string; CoreVersion string}; func New(Options) *Runtime, implements model.Runtime.

UI: React+TypeScript+Vite, Chinese, professional neutral/navy with teal accents, responsive navigation, real API only. Sections dashboard/nodes/upstreams/relays/jobs/settings; login/setup. Fetch state periodically while jobs run. API failure visibly reported, no hard-coded health metrics. No external QR service.

Dependencies: Go modernc SQLite, x/crypto/ssh, pkg/sftp, x/net. Frontend owns web/package.json and lock. Coordinate any new Go deps with parent. Avoid editing parent cmd/panel, go.mod, model. Each agent formats and tests owned code when compiler available. Parent integrates and runs remote checks. No credentials in repo, source files, test fixtures, or ordinary log output.
