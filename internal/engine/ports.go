package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func existingXrayProcess() bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if _, e := strconv.Atoi(entry.Name()); e != nil {
			continue
		}
		exe, e := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		if e != nil || strings.HasPrefix(exe, installRoot+"/") {
			continue
		}
		name := strings.ToLower(filepath.Base(strings.TrimSuffix(exe, " (deleted)")))
		if name == "xray" || strings.HasPrefix(name, "xray-linux-") {
			return true
		}
	}
	return false
}

// ownedSocketInodes identifies only sockets of this unit's exact MainPID.
func ownedSocketInodes(ctx context.Context) map[string]bool {
	inodes := map[string]bool{}
	if unitOwned() != nil {
		return inodes
	}
	pid, err := systemctl(ctx, "show", "--property=MainPID", "--value")
	if err != nil {
		return inodes
	}
	p, e := strconv.Atoi(strings.TrimSpace(pid))
	if e != nil || p <= 1 {
		return inodes
	}
	exe, e := os.Readlink(filepath.Join("/proc", pid, "exe"))
	if e != nil || !strings.HasPrefix(exe, installRoot+"/revisions/") {
		return inodes
	}
	fds, e := os.ReadDir(filepath.Join("/proc", pid, "fd"))
	if e != nil {
		return inodes
	}
	for _, fd := range fds {
		link, e := os.Readlink(filepath.Join("/proc", pid, "fd", fd.Name()))
		if e == nil && strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = true
		}
	}
	return inodes
}
func candidatePorts(config []byte) (map[int]bool, error) {
	var c struct {
		Inbounds []struct {
			Listen string `json:"listen"`
			Port   int    `json:"port"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(config, &c); err != nil {
		return nil, errors.New("invalid candidate inbound configuration")
	}
	ports := map[int]bool{}
	for _, in := range c.Inbounds {
		if in.Port < 1 || in.Port > 65535 {
			return nil, errors.New("candidate inbound port is invalid")
		}
		if ports[in.Port] {
			return nil, fmt.Errorf("duplicate candidate port %d", in.Port)
		}
		ports[in.Port] = true
	}
	return ports, nil
}
func ensurePortsAvailable(ctx context.Context, config []byte) error {
	wanted, err := candidatePorts(config)
	if err != nil {
		return err
	}
	owned := ownedSocketInodes(ctx)
	for _, p := range []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"} {
		b, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("cannot inspect node listening sockets: %w", err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 10 || (!strings.Contains(p, "udp") && f[3] != "0A") {
				continue
			}
			_, hexport, ok := strings.Cut(f[1], ":")
			if !ok {
				continue
			}
			port, e := strconv.ParseInt(hexport, 16, 32)
			if e == nil && wanted[int(port)] && !owned[f[9]] {
				return fmt.Errorf("candidate port %d is already in use by another process; existing services were not changed", port)
			}
		}
	}
	return nil
}
