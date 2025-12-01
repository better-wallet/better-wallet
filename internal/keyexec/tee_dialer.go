package keyexec

import (
	"context"
	"fmt"
	"net"
	"time"
)

// TEEDialer is an interface for connecting to TEE enclaves.
// Different TEE platforms (AWS Nitro, Azure SGX, GCP Confidential VM, etc.)
// can implement this interface to provide platform-specific connection handling.
type TEEDialer interface {
	// Dial creates a connection to the TEE enclave
	Dial(ctx context.Context) (net.Conn, error)

	// Platform returns the TEE platform name (e.g., "aws-nitro", "azure-sgx", "dev-tcp")
	Platform() string
}

// TEEPlatform represents supported TEE platforms
type TEEPlatform string

const (
	// TEEPlatformDev is for development/testing using TCP
	TEEPlatformDev TEEPlatform = "dev"

	// TEEPlatformAWSNitro is for AWS Nitro Enclaves (vsock)
	TEEPlatformAWSNitro TEEPlatform = "aws-nitro"

	// TEEPlatformAzureSGX is for Azure SGX enclaves (placeholder for future)
	// TEEPlatformAzureSGX TEEPlatform = "azure-sgx"

	// TEEPlatformGCPConfidential is for GCP Confidential VMs (placeholder for future)
	// TEEPlatformGCPConfidential TEEPlatform = "gcp-confidential"
)

// DevTCPDialer implements TEEDialer for development/testing using TCP
type DevTCPDialer struct {
	Host    string
	Port    uint32
	Timeout time.Duration
}

// NewDevTCPDialer creates a new development TCP dialer
func NewDevTCPDialer(port uint32, timeout time.Duration) *DevTCPDialer {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &DevTCPDialer{
		Host:    "127.0.0.1",
		Port:    port,
		Timeout: timeout,
	}
}

// Dial connects to the enclave via TCP (for development)
func (d *DevTCPDialer) Dial(ctx context.Context) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", d.Host, d.Port)
	dialer := net.Dialer{Timeout: d.Timeout}
	return dialer.DialContext(ctx, "tcp", addr)
}

// Platform returns the platform name
func (d *DevTCPDialer) Platform() string {
	return string(TEEPlatformDev)
}

// NitroVsockDialer implements TEEDialer for AWS Nitro Enclaves using vsock
// NOTE: This is a placeholder implementation. To use in production:
// 1. Add dependency: go get github.com/mdlayher/vsock
// 2. Uncomment the vsock import and Dial implementation below
type NitroVsockDialer struct {
	CID     uint32 // Context ID assigned by Nitro
	Port    uint32
	Timeout time.Duration
}

// NewNitroVsockDialer creates a new AWS Nitro vsock dialer
func NewNitroVsockDialer(cid, port uint32, timeout time.Duration) *NitroVsockDialer {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &NitroVsockDialer{
		CID:     cid,
		Port:    port,
		Timeout: timeout,
	}
}

// Dial connects to the enclave via vsock (Linux AF_VSOCK)
// This uses golang.org/x/sys/unix directly for vsock support
func (d *NitroVsockDialer) Dial(ctx context.Context) (net.Conn, error) {
	return dialVsock(ctx, d.CID, d.Port, d.Timeout)
}

// Platform returns the platform name
func (d *NitroVsockDialer) Platform() string {
	return string(TEEPlatformAWSNitro)
}

// NewTEEDialer creates a TEEDialer based on the platform configuration
func NewTEEDialer(cfg *TEEConfig) (TEEDialer, error) {
	platform := TEEPlatform(cfg.Platform)

	switch platform {
	case TEEPlatformDev:
		return NewDevTCPDialer(cfg.VsockPort, cfg.ConnectionTimeout), nil

	case TEEPlatformAWSNitro:
		if cfg.VsockCID == 0 {
			return nil, fmt.Errorf("TEE_VSOCK_CID is required for AWS Nitro platform")
		}
		return NewNitroVsockDialer(cfg.VsockCID, cfg.VsockPort, cfg.ConnectionTimeout), nil

	default:
		return nil, fmt.Errorf("unsupported TEE platform: %s (supported: %s, %s)",
			platform, TEEPlatformDev, TEEPlatformAWSNitro)
	}
}

// Ensure dialers implement TEEDialer
var (
	_ TEEDialer = (*DevTCPDialer)(nil)
	_ TEEDialer = (*NitroVsockDialer)(nil)
)
