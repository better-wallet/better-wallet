package api

import (
	"testing"

	"github.com/better-wallet/better-wallet/pkg/types"
)

func TestHasOperation(t *testing.T) {
	h := &AgentSigningHandlers{}

	tests := []struct {
		name       string
		credential *types.AgentCredential
		operation  string
		want       bool
	}{
		{
			name: "empty operations list allows all",
			credential: &types.AgentCredential{
				Capabilities: types.AgentCapabilities{
					Operations: []string{},
				},
			},
			operation: types.OperationTransfer,
			want:      true,
		},
		{
			name: "nil operations list allows all",
			credential: &types.AgentCredential{
				Capabilities: types.AgentCapabilities{},
			},
			operation: types.OperationSignMessage,
			want:      true,
		},
		{
			name: "wildcard allows all",
			credential: &types.AgentCredential{
				Capabilities: types.AgentCapabilities{
					Operations: []string{"*"},
				},
			},
			operation: types.OperationContractDeploy,
			want:      true,
		},
		{
			name: "exact match",
			credential: &types.AgentCredential{
				Capabilities: types.AgentCapabilities{
					Operations: []string{types.OperationTransfer, types.OperationSwap},
				},
			},
			operation: types.OperationTransfer,
			want:      true,
		},
		{
			name: "operation not in list",
			credential: &types.AgentCredential{
				Capabilities: types.AgentCapabilities{
					Operations: []string{types.OperationTransfer},
				},
			},
			operation: types.OperationContractDeploy,
			want:      false,
		},
		{
			name: "sign_message allowed",
			credential: &types.AgentCredential{
				Capabilities: types.AgentCapabilities{
					Operations: []string{types.OperationSignMessage, types.OperationSignTypedData},
				},
			},
			operation: types.OperationSignMessage,
			want:      true,
		},
		{
			name: "sign_typed_data not in list",
			credential: &types.AgentCredential{
				Capabilities: types.AgentCapabilities{
					Operations: []string{types.OperationTransfer},
				},
			},
			operation: types.OperationSignTypedData,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := h.hasOperation(tt.credential, tt.operation)
			if got != tt.want {
				t.Errorf("hasOperation() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsContractAllowed(t *testing.T) {
	h := &AgentSigningHandlers{}

	tests := []struct {
		name       string
		credential *types.AgentCredential
		to         string
		want       bool
	}{
		{
			name: "empty to address",
			credential: &types.AgentCredential{
				Capabilities: types.AgentCapabilities{
					AllowedContracts: []string{"0x1234567890123456789012345678901234567890"},
				},
			},
			to:   "",
			want: false,
		},
		{
			name: "exact match",
			credential: &types.AgentCredential{
				Capabilities: types.AgentCapabilities{
					AllowedContracts: []string{"0x1234567890123456789012345678901234567890"},
				},
			},
			to:   "0x1234567890123456789012345678901234567890",
			want: true,
		},
		{
			name: "case insensitive match - lowercase in list",
			credential: &types.AgentCredential{
				Capabilities: types.AgentCapabilities{
					AllowedContracts: []string{"0x1234567890abcdef1234567890abcdef12345678"},
				},
			},
			to:   "0x1234567890ABCDEF1234567890ABCDEF12345678",
			want: true,
		},
		{
			name: "case insensitive match - uppercase in list",
			credential: &types.AgentCredential{
				Capabilities: types.AgentCapabilities{
					AllowedContracts: []string{"0x1234567890ABCDEF1234567890ABCDEF12345678"},
				},
			},
			to:   "0x1234567890abcdef1234567890abcdef12345678",
			want: true,
		},
		{
			name: "not in allowlist",
			credential: &types.AgentCredential{
				Capabilities: types.AgentCapabilities{
					AllowedContracts: []string{
						"0x1111111111111111111111111111111111111111",
						"0x2222222222222222222222222222222222222222",
					},
				},
			},
			to:   "0x3333333333333333333333333333333333333333",
			want: false,
		},
		{
			name: "multiple contracts - match second",
			credential: &types.AgentCredential{
				Capabilities: types.AgentCapabilities{
					AllowedContracts: []string{
						"0x1111111111111111111111111111111111111111",
						"0x2222222222222222222222222222222222222222",
						"0x3333333333333333333333333333333333333333",
					},
				},
			},
			to:   "0x2222222222222222222222222222222222222222",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := h.isContractAllowed(tt.credential, tt.to)
			if got != tt.want {
				t.Errorf("isContractAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetString(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]any
		key  string
		want string
	}{
		{
			name: "string value",
			m:    map[string]any{"key": "value"},
			key:  "key",
			want: "value",
		},
		{
			name: "missing key",
			m:    map[string]any{"other": "value"},
			key:  "key",
			want: "",
		},
		{
			name: "non-string value",
			m:    map[string]any{"key": 123},
			key:  "key",
			want: "",
		},
		{
			name: "nil value",
			m:    map[string]any{"key": nil},
			key:  "key",
			want: "",
		},
		{
			name: "empty map",
			m:    map[string]any{},
			key:  "key",
			want: "",
		},
		{
			name: "empty string value",
			m:    map[string]any{"key": ""},
			key:  "key",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getString(tt.m, tt.key)
			if got != tt.want {
				t.Errorf("getString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStripHexPrefixAPI(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"0x1234", "1234"},
		{"0X1234", "0X1234"}, // only lowercase 0x
		{"1234", "1234"},
		{"0x", ""},
		{"", ""},
		{"0xabcdef", "abcdef"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := stripHexPrefix(tt.input)
			if got != tt.want {
				t.Errorf("stripHexPrefix(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
