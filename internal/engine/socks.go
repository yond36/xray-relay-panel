package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// Only RFC1929 authentication is offered. An unrelated or misconfigured no-auth
// SOCKS listener must not be accepted if it wins a loopback port allocation race.
func dialProbeSOCKS(ctx context.Context, address, user, pass, target string) (net.Conn, error) {
	if len(user) == 0 || len(user) > 255 || len(pass) == 0 || len(pass) > 255 {
		return nil, errors.New("invalid probe SOCKS credentials")
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid proxy destination port")
	}
	if len(host) == 0 || len(host) > 255 {
		return nil, errors.New("invalid proxy destination host")
	}
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("connect isolated SOCKS probe: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline := time.Now().Add(10 * time.Second)
	if d, has := ctx.Deadline(); has && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte{5, 1, 2}); err != nil {
		return nil, err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, err
	}
	if reply[0] != 5 || reply[1] != 2 {
		return nil, errors.New("isolated SOCKS probe refused mandatory authentication")
	}
	auth := append([]byte{1, byte(len(user))}, []byte(user)...)
	auth = append(auth, byte(len(pass)))
	auth = append(auth, []byte(pass)...)
	if _, err := conn.Write(auth); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, err
	}
	if reply[0] != 1 || reply[1] != 0 {
		return nil, errors.New("isolated SOCKS probe authentication failed")
	}
	request := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			request = append(request, 1)
			request = append(request, ip4...)
		} else {
			request = append(request, 4)
			request = append(request, ip.To16()...)
		}
	} else { // SOCKS5h: preserve the hostname; never resolve it on the panel host.
		request = append(request, 3, byte(len(host)))
		request = append(request, []byte(host)...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != 5 || header[1] != 0 || header[2] != 0 {
		return nil, errors.New("requested upstream could not establish proxy egress")
	}
	n := 0
	switch header[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		size := []byte{0}
		if _, err := io.ReadFull(conn, size); err != nil {
			return nil, err
		}
		n = int(size[0])
	default:
		return nil, errors.New("invalid SOCKS response address")
	}
	if _, err := io.CopyN(io.Discard, conn, int64(n+2)); err != nil {
		return nil, err
	}
	if !stop() && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	_ = conn.SetDeadline(time.Time{})
	ok = true
	return conn, nil
}
