//go:build !linux

package engine

import (
	"context"
	"errors"
)

func lockNode(context.Context) (func(), error) {
	return nil, errors.New("node management requires Linux with systemd")
}
