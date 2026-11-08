package model

import (
	"context"
	"encoding/json"
	"time"
)

const Version = "0.2.5"
const DefaultCoreVersion = "v26.10.31"

const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// User is the public account identity. Credentials and subscription tokens are
// deliberately kept out of this type, including when an administrator lists users.
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

func (u User) IsAdmin() bool { return u.Role == RoleAdmin }

func (u User) CanAccess(ownerID string) bool {
	return u.ID != "" && (u.IsAdmin() || u.ID == ownerID)
}

type Node struct {
	OwnerID         string    `json:"owner_id,omitempty"`
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Kind            string    `json:"kind"`
	Host            string    `json:"host"`
	SSHPort         int       `json:"ssh_port"`
	Username        string    `json:"username"`
	AuthMode        string    `json:"auth_mode"`
	Password        string    `json:"password,omitempty"`
	PrivateKey      string    `json:"private_key,omitempty"`
	KeyPassphrase   string    `json:"key_passphrase,omitempty"`
	Fingerprint     string    `json:"fingerprint"`
	PublicHost      string    `json:"public_host"`
	CoreVersion     string    `json:"core_version"`
	Status          string    `json:"status"`
	LastError       string    `json:"last_error,omitempty"`
	AppliedRevision string    `json:"applied_revision,omitempty"`
	HasCredentials  bool      `json:"has_credentials"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type Upstream struct {
	OwnerID   string          `json:"owner_id,omitempty"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Protocol  string          `json:"protocol"`
	Server    string          `json:"server"`
	Port      int             `json:"port"`
	Outbound  json.RawMessage `json:"outbound,omitempty"`
	SourceID  string          `json:"source_id,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type Relay struct {
	OwnerID           string    `json:"owner_id,omitempty"`
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	NodeID            string    `json:"node_id"`
	UpstreamID        string    `json:"upstream_id"`
	Enabled           bool      `json:"enabled"`
	Protocol          string    `json:"protocol"`
	Listen            string    `json:"listen"`
	PublicHost        string    `json:"public_host"`
	Port              int       `json:"port"`
	Network           string    `json:"network"`
	Security          string    `json:"security"`
	UUID              string    `json:"uuid,omitempty"`
	Password          string    `json:"password,omitempty"`
	Cipher            string    `json:"cipher,omitempty"`
	Flow              string    `json:"flow,omitempty"`
	ServerName        string    `json:"server_name,omitempty"`
	Target            string    `json:"target,omitempty"`
	RealityPrivateKey string    `json:"reality_private_key,omitempty"`
	RealityPublicKey  string    `json:"reality_public_key,omitempty"`
	ShortID           string    `json:"short_id,omitempty"`
	Path              string    `json:"path,omitempty"`
	Certificate       string    `json:"certificate,omitempty"`
	CertificateKey    string    `json:"certificate_key,omitempty"`
	ShareURL          string    `json:"share_url,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type Job struct {
	OwnerID    string     `json:"owner_id,omitempty"`
	ID         string     `json:"id"`
	NodeID     string     `json:"node_id"`
	UpstreamID string     `json:"upstream_id,omitempty"`
	Action     string     `json:"action"`
	Status     string     `json:"status"`
	Message    string     `json:"message"`
	Error      string     `json:"error,omitempty"`
	Revision   string     `json:"revision,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

type ProbeResult struct {
	OwnerID    string    `json:"owner_id,omitempty"`
	ID         string    `json:"id"`
	JobID      string    `json:"job_id,omitempty"`
	NodeID     string    `json:"node_id"`
	UpstreamID string    `json:"upstream_id"`
	IPv4       string    `json:"ipv4,omitempty"`
	IPv6       string    `json:"ipv6,omitempty"`
	LatencyMS  int64     `json:"latency_ms"`
	Status     string    `json:"status"`
	Error      string    `json:"error,omitempty"`
	IPv6Error  string    `json:"ipv6_error,omitempty"`
	CheckedAt  time.Time `json:"checked_at"`
}

type NodeInspection struct {
	Fingerprint   string `json:"fingerprint"`
	RequiresTrust bool   `json:"requires_trust"`
	OS            string `json:"os"`
	Architecture  string `json:"architecture"`
	ServiceState  string `json:"service_state"`
	CoreVersion   string `json:"core_version"`
	ExistingXray  bool   `json:"existing_xray"`
	Ports         []int  `json:"ports"`
	Message       string `json:"message"`
}

type ApplyResult struct {
	Revision    string `json:"revision"`
	CoreVersion string `json:"core_version"`
	Message     string `json:"message"`
}

type Subscription struct {
	OwnerID   string    `json:"owner_id,omitempty"`
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	URL       string    `json:"url,omitempty"`
	Count     int       `json:"count"`
	LastError string    `json:"last_error,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Settings struct {
	RegistrationOpen  bool   `json:"registration_open"`
	SubscriptionToken string `json:"subscription_token,omitempty"`
	PanelURL          string `json:"panel_url"`
	CoreVersion       string `json:"core_version"`
}

type State struct {
	CurrentUser   *User          `json:"current_user"`
	Users         []User         `json:"users"`
	Nodes         []Node         `json:"nodes"`
	Upstreams     []Upstream     `json:"upstreams"`
	Relays        []Relay        `json:"relays"`
	Jobs          []Job          `json:"jobs"`
	Probes        []ProbeResult  `json:"probes"`
	Subscriptions []Subscription `json:"subscriptions"`
	Settings      Settings       `json:"settings"`
}

// Runtime owns only the panel's isolated Xray installation on each node.
type Runtime interface {
	Inspect(context.Context, Node) (NodeInspection, error)
	Apply(context.Context, Node, []Upstream, []Relay) (ApplyResult, error)
	Probe(context.Context, Node, Upstream) (ProbeResult, error)
	Service(context.Context, Node, string) error
	Logs(context.Context, Node) (string, error)
}
