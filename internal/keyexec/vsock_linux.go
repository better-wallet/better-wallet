//go:build linux

package keyexec

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// vsockConn wraps a file descriptor to implement net.Conn
type vsockConn struct {
	fd      int
	remote  *unix.SockaddrVM
	timeout time.Duration
}

// dialVsock connects to a vsock endpoint on Linux
func dialVsock(ctx context.Context, cid, port uint32, timeout time.Duration) (net.Conn, error) {
	// Create vsock socket
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create vsock socket: %w", err)
	}

	// Set non-blocking for context cancellation support
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to set non-blocking: %w", err)
	}

	remote := &unix.SockaddrVM{
		CID:  cid,
		Port: port,
	}

	// Attempt connection
	err = unix.Connect(fd, remote)
	if err != nil {
		if err != unix.EINPROGRESS {
			unix.Close(fd)
			return nil, fmt.Errorf("vsock connect failed: %w", err)
		}

		// Wait for connection with context/timeout
		deadline := time.Now().Add(timeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}

		// Use poll to wait for connection
		for {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				unix.Close(fd)
				return nil, fmt.Errorf("vsock connect timeout")
			}

			// Check context cancellation
			select {
			case <-ctx.Done():
				unix.Close(fd)
				return nil, ctx.Err()
			default:
			}

			// Poll for write-ready (indicates connection complete)
			pollFds := []unix.PollFd{{
				Fd:     int32(fd),
				Events: unix.POLLOUT,
			}}

			timeoutMs := int(remaining.Milliseconds())
			if timeoutMs < 1 {
				timeoutMs = 1
			}

			n, err := unix.Poll(pollFds, timeoutMs)
			if err != nil {
				if err == unix.EINTR {
					continue
				}
				unix.Close(fd)
				return nil, fmt.Errorf("poll failed: %w", err)
			}

			if n > 0 {
				// Check for connection error
				sockerr, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
				if err != nil {
					unix.Close(fd)
					return nil, fmt.Errorf("getsockopt failed: %w", err)
				}
				if sockerr != 0 {
					unix.Close(fd)
					return nil, fmt.Errorf("vsock connect error: %w", unix.Errno(sockerr))
				}
				break
			}
		}
	}

	// Set back to blocking mode for normal I/O
	if err := unix.SetNonblock(fd, false); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to set blocking: %w", err)
	}

	return &vsockConn{
		fd:      fd,
		remote:  remote,
		timeout: timeout,
	}, nil
}

// Read implements net.Conn
func (c *vsockConn) Read(b []byte) (int, error) {
	n, err := unix.Read(c.fd, b)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Write implements net.Conn
func (c *vsockConn) Write(b []byte) (int, error) {
	return unix.Write(c.fd, b)
}

// Close implements net.Conn
func (c *vsockConn) Close() error {
	return unix.Close(c.fd)
}

// LocalAddr implements net.Conn
func (c *vsockConn) LocalAddr() net.Addr {
	return &vsockAddr{cid: unix.VMADDR_CID_ANY, port: 0}
}

// RemoteAddr implements net.Conn
func (c *vsockConn) RemoteAddr() net.Addr {
	return &vsockAddr{cid: c.remote.CID, port: c.remote.Port}
}

// SetDeadline implements net.Conn
func (c *vsockConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetReadDeadline implements net.Conn
func (c *vsockConn) SetReadDeadline(t time.Time) error {
	var timeout unix.Timeval
	if !t.IsZero() {
		d := time.Until(t)
		if d > 0 {
			timeout.Sec = int64(d / time.Second)
			timeout.Usec = int64((d % time.Second) / time.Microsecond)
		}
	}
	return unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout)
}

// SetWriteDeadline implements net.Conn
func (c *vsockConn) SetWriteDeadline(t time.Time) error {
	var timeout unix.Timeval
	if !t.IsZero() {
		d := time.Until(t)
		if d > 0 {
			timeout.Sec = int64(d / time.Second)
			timeout.Usec = int64((d % time.Second) / time.Microsecond)
		}
	}
	return unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &timeout)
}

// vsockAddr implements net.Addr for vsock
type vsockAddr struct {
	cid  uint32
	port uint32
}

func (a *vsockAddr) Network() string { return "vsock" }
func (a *vsockAddr) String() string  { return fmt.Sprintf("%d:%d", a.cid, a.port) }

// Ensure vsockConn implements net.Conn
var _ net.Conn = (*vsockConn)(nil)
