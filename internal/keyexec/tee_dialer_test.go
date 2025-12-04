package keyexec

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTEEPlatformConstants(t *testing.T) {
	assert.Equal(t, TEEPlatform("dev"), TEEPlatformDev)
	assert.Equal(t, TEEPlatform("aws-nitro"), TEEPlatformAWSNitro)
}

func TestNewDevTCPDialer(t *testing.T) {
	t.Run("creates dialer with default timeout", func(t *testing.T) {
		dialer := NewDevTCPDialer(5000, 0)
		require.NotNil(t, dialer)

		assert.Equal(t, "127.0.0.1", dialer.Host)
		assert.Equal(t, uint32(5000), dialer.Port)
		assert.Equal(t, 30*time.Second, dialer.Timeout)
	})

	t.Run("creates dialer with custom timeout", func(t *testing.T) {
		dialer := NewDevTCPDialer(5000, 10*time.Second)
		require.NotNil(t, dialer)

		assert.Equal(t, uint32(5000), dialer.Port)
		assert.Equal(t, 10*time.Second, dialer.Timeout)
	})
}

func TestDevTCPDialer_Platform(t *testing.T) {
	dialer := NewDevTCPDialer(5000, 0)
	assert.Equal(t, string(TEEPlatformDev), dialer.Platform())
}

func TestDevTCPDialer_Dial(t *testing.T) {
	t.Run("connects to running server", func(t *testing.T) {
		// Start a test server
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer listener.Close()

		// Get the port
		addr := listener.Addr().(*net.TCPAddr)
		port := uint32(addr.Port)

		// Accept connections in background
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}()

		dialer := NewDevTCPDialer(port, 5*time.Second)
		ctx := context.Background()

		conn, err := dialer.Dial(ctx)
		require.NoError(t, err)
		require.NotNil(t, conn)
		conn.Close()
	})

	t.Run("returns error when no server", func(t *testing.T) {
		dialer := NewDevTCPDialer(59999, 1*time.Second) // Port unlikely to be in use
		ctx := context.Background()

		conn, err := dialer.Dial(ctx)
		assert.Error(t, err)
		assert.Nil(t, conn)
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		dialer := NewDevTCPDialer(59999, 30*time.Second)

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		conn, err := dialer.Dial(ctx)
		assert.Error(t, err)
		assert.Nil(t, conn)
	})
}

func TestNewNitroVsockDialer(t *testing.T) {
	t.Run("creates dialer with default timeout", func(t *testing.T) {
		dialer := NewNitroVsockDialer(3, 5000, 0)
		require.NotNil(t, dialer)

		assert.Equal(t, uint32(3), dialer.CID)
		assert.Equal(t, uint32(5000), dialer.Port)
		assert.Equal(t, 30*time.Second, dialer.Timeout)
	})

	t.Run("creates dialer with custom timeout", func(t *testing.T) {
		dialer := NewNitroVsockDialer(4, 6000, 15*time.Second)
		require.NotNil(t, dialer)

		assert.Equal(t, uint32(4), dialer.CID)
		assert.Equal(t, uint32(6000), dialer.Port)
		assert.Equal(t, 15*time.Second, dialer.Timeout)
	})
}

func TestNitroVsockDialer_Platform(t *testing.T) {
	dialer := NewNitroVsockDialer(3, 5000, 0)
	assert.Equal(t, string(TEEPlatformAWSNitro), dialer.Platform())
}

func TestNewTEEDialer(t *testing.T) {
	t.Run("creates dev dialer", func(t *testing.T) {
		cfg := &TEEConfig{
			Platform:  "dev",
			VsockPort: 5000,
		}

		dialer, err := NewTEEDialer(cfg)
		require.NoError(t, err)
		require.NotNil(t, dialer)
		assert.Equal(t, string(TEEPlatformDev), dialer.Platform())
	})

	t.Run("creates aws-nitro dialer", func(t *testing.T) {
		cfg := &TEEConfig{
			Platform:  "aws-nitro",
			VsockCID:  3,
			VsockPort: 5000,
		}

		dialer, err := NewTEEDialer(cfg)
		require.NoError(t, err)
		require.NotNil(t, dialer)
		assert.Equal(t, string(TEEPlatformAWSNitro), dialer.Platform())
	})

	t.Run("returns error for aws-nitro without CID", func(t *testing.T) {
		cfg := &TEEConfig{
			Platform:  "aws-nitro",
			VsockPort: 5000,
			// VsockCID is 0 (not set)
		}

		dialer, err := NewTEEDialer(cfg)
		assert.Error(t, err)
		assert.Nil(t, dialer)
		assert.Contains(t, err.Error(), "TEE_VSOCK_CID is required")
	})

	t.Run("returns error for unsupported platform", func(t *testing.T) {
		cfg := &TEEConfig{
			Platform: "unsupported-platform",
		}

		dialer, err := NewTEEDialer(cfg)
		assert.Error(t, err)
		assert.Nil(t, dialer)
		assert.Contains(t, err.Error(), "unsupported TEE platform")
	})
}

func TestTEEDialerInterfaceCompliance(t *testing.T) {
	// Verify interface compliance at compile time
	var _ TEEDialer = (*DevTCPDialer)(nil)
	var _ TEEDialer = (*NitroVsockDialer)(nil)
}
