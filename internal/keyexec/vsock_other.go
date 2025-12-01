//go:build !linux

package keyexec

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"time"
)

// dialVsock is not supported on non-Linux platforms
func dialVsock(ctx context.Context, cid, port uint32, timeout time.Duration) (net.Conn, error) {
	return nil, fmt.Errorf("vsock is only supported on Linux (current OS: %s). AWS Nitro Enclaves require Linux", runtime.GOOS)
}
