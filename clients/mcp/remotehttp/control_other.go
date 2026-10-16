//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package remotehttp

import (
	"context"
	"net"
)

func listenControl(string) (net.Listener, error) { return nil, errPlatform }
func callControl(context.Context, string, string) (OperatorResult, bool, error) {
	return OperatorResult{}, false, errPlatform
}
