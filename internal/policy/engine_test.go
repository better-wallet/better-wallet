package policy

import (
	"context"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
)

func TestEngineEvaluate_FieldSourceOperatorSchema(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	tests := []struct {
		name     string
		policy   *types.Policy
		evalCtx  *EvaluationContext
		expected PolicyDecision
	}{
		{
			name: "allow_transaction_to_whitelisted_address",
			policy: &types.Policy{
				ID:        uuid.New(),
				Name:      "Allow USDC",
				ChainType: "ethereum",
				Version:   "1.0",
				Rules: map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"name":   "Allow USDC contract",
							"method": "eth_sendTransaction",
							"action": "ALLOW",
							"conditions": []interface{}{
								map[string]interface{}{
									"field_source": "ethereum_transaction",
									"field":        "to",
									"operator":     "eq",
									"value":        "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
								},
							},
						},
					},
				},
			},
			evalCtx: &EvaluationContext{
				ChainType: "ethereum",
				Method:    "eth_sendTransaction",
				To:        strPtr("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
				Value:     big.NewInt(0),
				Timestamp: time.Now(),
			},
			expected: DecisionAllow,
		},
		{
			name: "deny_transaction_to_non_whitelisted_address",
			policy: &types.Policy{
				ID:        uuid.New(),
				Name:      "Allow USDC only",
				ChainType: "ethereum",
				Version:   "1.0",
				Rules: map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"name":   "Allow USDC contract",
							"method": "eth_sendTransaction",
							"action": "ALLOW",
							"conditions": []interface{}{
								map[string]interface{}{
									"field_source": "ethereum_transaction",
									"field":        "to",
									"operator":     "eq",
									"value":        "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
								},
							},
						},
					},
				},
			},
			evalCtx: &EvaluationContext{
				ChainType: "ethereum",
				Method:    "eth_sendTransaction",
				To:        strPtr("0x1234567890abcdef1234567890abcdef12345678"),
				Value:     big.NewInt(0),
				Timestamp: time.Now(),
			},
			expected: DecisionDeny,
		},
		{
			name: "allow_value_within_limit_lte",
			policy: &types.Policy{
				ID:        uuid.New(),
				Name:      "Max value policy",
				ChainType: "ethereum",
				Version:   "1.0",
				Rules: map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"name":   "Allow small transactions",
							"method": "eth_sendTransaction",
							"action": "ALLOW",
							"conditions": []interface{}{
								map[string]interface{}{
									"field_source": "ethereum_transaction",
									"field":        "value",
									"operator":     "lte",
									"value":        "1000000000000000000", // 1 ETH in wei
								},
							},
						},
					},
				},
			},
			evalCtx: &EvaluationContext{
				ChainType: "ethereum",
				Method:    "eth_sendTransaction",
				To:        strPtr("0x1234567890abcdef1234567890abcdef12345678"),
				Value:     big.NewInt(500000000000000000), // 0.5 ETH
				Timestamp: time.Now(),
			},
			expected: DecisionAllow,
		},
		{
			name: "deny_value_exceeds_limit_lte",
			policy: &types.Policy{
				ID:        uuid.New(),
				Name:      "Max value policy",
				ChainType: "ethereum",
				Version:   "1.0",
				Rules: map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"name":   "Allow small transactions",
							"method": "eth_sendTransaction",
							"action": "ALLOW",
							"conditions": []interface{}{
								map[string]interface{}{
									"field_source": "ethereum_transaction",
									"field":        "value",
									"operator":     "lte",
									"value":        "1000000000000000000", // 1 ETH in wei
								},
							},
						},
					},
				},
			},
			evalCtx: &EvaluationContext{
				ChainType: "ethereum",
				Method:    "eth_sendTransaction",
				To:        strPtr("0x1234567890abcdef1234567890abcdef12345678"),
				Value:     big.NewInt(2000000000000000000), // 2 ETH
				Timestamp: time.Now(),
			},
			expected: DecisionDeny,
		},
		{
			name: "allow_address_in_list",
			policy: &types.Policy{
				ID:        uuid.New(),
				Name:      "Allowlist policy",
				ChainType: "ethereum",
				Version:   "1.0",
				Rules: map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"name":   "Allow approved addresses",
							"method": "*",
							"action": "ALLOW",
							"conditions": []interface{}{
								map[string]interface{}{
									"field_source": "ethereum_transaction",
									"field":        "to",
									"operator":     "in",
									"value": []interface{}{
										"0xaaa0000000000000000000000000000000000000",
										"0xbbb0000000000000000000000000000000000000",
										"0xccc0000000000000000000000000000000000000",
									},
								},
							},
						},
					},
				},
			},
			evalCtx: &EvaluationContext{
				ChainType: "ethereum",
				Method:    "eth_sendTransaction",
				To:        strPtr("0xbbb0000000000000000000000000000000000000"),
				Value:     big.NewInt(0),
				Timestamp: time.Now(),
			},
			expected: DecisionAllow,
		},
		{
			name: "deny_address_not_in_list",
			policy: &types.Policy{
				ID:        uuid.New(),
				Name:      "Allowlist policy",
				ChainType: "ethereum",
				Version:   "1.0",
				Rules: map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"name":   "Allow approved addresses",
							"method": "*",
							"action": "ALLOW",
							"conditions": []interface{}{
								map[string]interface{}{
									"field_source": "ethereum_transaction",
									"field":        "to",
									"operator":     "in",
									"value": []interface{}{
										"0xaaa0000000000000000000000000000000000000",
										"0xbbb0000000000000000000000000000000000000",
									},
								},
							},
						},
					},
				},
			},
			evalCtx: &EvaluationContext{
				ChainType: "ethereum",
				Method:    "eth_sendTransaction",
				To:        strPtr("0xddd0000000000000000000000000000000000000"),
				Value:     big.NewInt(0),
				Timestamp: time.Now(),
			},
			expected: DecisionDeny,
		},
		{
			name: "typed_data_domain_check",
			policy: &types.Policy{
				ID:        uuid.New(),
				Name:      "Typed data policy",
				ChainType: "ethereum",
				Version:   "1.0",
				Rules: map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"name":   "Allow specific chain",
							"method": "eth_signTypedData_v4",
							"action": "ALLOW",
							"conditions": []interface{}{
								map[string]interface{}{
									"field_source": "ethereum_typed_data_domain",
									"field":        "chainId",
									"operator":     "eq",
									"value":        float64(1), // JSON numbers are float64
								},
							},
						},
					},
				},
			},
			evalCtx: &EvaluationContext{
				ChainType: "ethereum",
				Method:    "eth_signTypedData_v4",
				TypedDataDomain: map[string]interface{}{
					"chainId":           float64(1),
					"verifyingContract": "0x1234567890abcdef1234567890abcdef12345678",
				},
				Timestamp: time.Now(),
			},
			expected: DecisionAllow,
		},
		{
			name: "system_timestamp_check",
			policy: &types.Policy{
				ID:        uuid.New(),
				Name:      "Time-based policy",
				ChainType: "ethereum",
				Version:   "1.0",
				Rules: map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"name":   "Allow after timestamp",
							"method": "*",
							"action": "ALLOW",
							"conditions": []interface{}{
								map[string]interface{}{
									"field_source": "system",
									"field":        "current_unix_timestamp",
									"operator":     "gte",
									"value":        float64(0), // Any time after Unix epoch
								},
							},
						},
					},
				},
			},
			evalCtx: &EvaluationContext{
				ChainType: "ethereum",
				Method:    "eth_sendTransaction",
				To:        strPtr("0x1234567890abcdef1234567890abcdef12345678"),
				Value:     big.NewInt(0),
				Timestamp: time.Now(),
			},
			expected: DecisionAllow,
		},
		{
			name: "no_policies_allows_by_default",
			policy: nil,
			evalCtx: &EvaluationContext{
				ChainType: "ethereum",
				Method:    "eth_sendTransaction",
				Timestamp: time.Now(),
			},
			expected: DecisionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var policies []*types.Policy
			if tt.policy != nil {
				policies = []*types.Policy{tt.policy}
			}

			result, err := engine.Evaluate(ctx, policies, tt.evalCtx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Decision != tt.expected {
				t.Errorf("expected %v, got %v (reason: %s)", tt.expected, result.Decision, result.Reason)
			}
		})
	}
}

func TestEngineValidatePolicy(t *testing.T) {
	engine := NewEngine()

	tests := []struct {
		name      string
		policy    *types.Policy
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid_policy",
			policy: &types.Policy{
				Name:      "Test Policy",
				ChainType: "ethereum",
				Rules: map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"name":   "Test rule",
							"method": "*",
							"action": "ALLOW",
							"conditions": []interface{}{
								map[string]interface{}{
									"field_source": "ethereum_transaction",
									"field":        "to",
									"operator":     "eq",
									"value":        "0x1234",
								},
							},
						},
					},
				},
			},
			expectErr: false,
		},
		{
			name: "missing_name",
			policy: &types.Policy{
				ChainType: "ethereum",
				Rules:     map[string]interface{}{"rules": []interface{}{}},
			},
			expectErr: true,
			errMsg:    "policy name is required",
		},
		{
			name: "missing_chain_type",
			policy: &types.Policy{
				Name:  "Test",
				Rules: map[string]interface{}{"rules": []interface{}{}},
			},
			expectErr: true,
			errMsg:    "chain type is required",
		},
		{
			name: "empty_rules",
			policy: &types.Policy{
				Name:      "Test",
				ChainType: "ethereum",
				Rules:     map[string]interface{}{"rules": []interface{}{}},
			},
			expectErr: true,
			errMsg:    "at least one rule is required",
		},
		{
			name: "missing_method",
			policy: &types.Policy{
				Name:      "Test Policy",
				ChainType: "ethereum",
				Rules: map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"name":       "Test rule",
							"action":     "ALLOW",
							"conditions": []interface{}{},
						},
					},
				},
			},
			expectErr: true,
			errMsg:    "missing 'method' field",
		},
		{
			name: "missing_action",
			policy: &types.Policy{
				Name:      "Test Policy",
				ChainType: "ethereum",
				Rules: map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"name":       "Test rule",
							"method":     "*",
							"conditions": []interface{}{},
						},
					},
				},
			},
			expectErr: true,
			errMsg:    "missing 'action' field",
		},
		{
			name: "invalid_action",
			policy: &types.Policy{
				Name:      "Test Policy",
				ChainType: "ethereum",
				Rules: map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"name":       "Test rule",
							"method":     "*",
							"action":     "INVALID_ACTION",
							"conditions": []interface{}{},
						},
					},
				},
			},
			expectErr: true,
			errMsg:    "invalid action",
		},
		{
			name: "missing_field_source",
			policy: &types.Policy{
				Name:      "Test Policy",
				ChainType: "ethereum",
				Rules: map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"name":   "Test rule",
							"method": "*",
							"action": "ALLOW",
							"conditions": []interface{}{
								map[string]interface{}{
									"field":    "to",
									"operator": "eq",
									"value":    "0x1234",
								},
							},
						},
					},
				},
			},
			expectErr: true,
			errMsg:    "missing 'field_source'",
		},
		{
			name: "invalid_field_source",
			policy: &types.Policy{
				Name:      "Test Policy",
				ChainType: "ethereum",
				Rules: map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"name":   "Test rule",
							"method": "*",
							"action": "ALLOW",
							"conditions": []interface{}{
								map[string]interface{}{
									"field_source": "invalid_source",
									"field":        "to",
									"operator":     "eq",
									"value":        "0x1234",
								},
							},
						},
					},
				},
			},
			expectErr: true,
			errMsg:    "invalid field_source",
		},
		{
			name: "invalid_operator",
			policy: &types.Policy{
				Name:      "Test Policy",
				ChainType: "ethereum",
				Rules: map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"name":   "Test rule",
							"method": "*",
							"action": "ALLOW",
							"conditions": []interface{}{
								map[string]interface{}{
									"field_source": "ethereum_transaction",
									"field":        "to",
									"operator":     "invalid_op",
									"value":        "0x1234",
								},
							},
						},
					},
				},
			},
			expectErr: true,
			errMsg:    "invalid operator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := engine.ValidatePolicy(tt.policy)
			if tt.expectErr && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.expectErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errMsg, err.Error())
				}
			}
		})
	}
}

// TestConditionSetOperator tests the in_condition_set operator
func TestConditionSetOperator(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	// Policy using in_condition_set operator
	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Condition Set Policy",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Allow approved addresses",
					"method": "eth_sendTransaction",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "to",
							"operator":     "in_condition_set",
							"value":        "approved-addresses-set-id",
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name          string
		conditionSets map[string][]interface{}
		toAddress     string
		expected      PolicyDecision
	}{
		{
			name: "address_in_condition_set",
			conditionSets: map[string][]interface{}{
				"approved-addresses-set-id": {
					"0xaaa0000000000000000000000000000000000000",
					"0xbbb0000000000000000000000000000000000000",
					"0xccc0000000000000000000000000000000000000",
				},
			},
			toAddress: "0xbbb0000000000000000000000000000000000000",
			expected:  DecisionAllow,
		},
		{
			name: "address_not_in_condition_set",
			conditionSets: map[string][]interface{}{
				"approved-addresses-set-id": {
					"0xaaa0000000000000000000000000000000000000",
					"0xbbb0000000000000000000000000000000000000",
				},
			},
			toAddress: "0xddd0000000000000000000000000000000000000",
			expected:  DecisionDeny,
		},
		{
			name:          "condition_set_not_found",
			conditionSets: map[string][]interface{}{},
			toAddress:     "0xaaa0000000000000000000000000000000000000",
			expected:      DecisionDeny,
		},
		{
			name:          "nil_condition_sets",
			conditionSets: nil,
			toAddress:     "0xaaa0000000000000000000000000000000000000",
			expected:      DecisionDeny,
		},
		{
			name: "case_insensitive_address_match",
			conditionSets: map[string][]interface{}{
				"approved-addresses-set-id": {
					"0xAAA0000000000000000000000000000000000000",
				},
			},
			toAddress: "0xaaa0000000000000000000000000000000000000",
			expected:  DecisionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evalCtx := &EvaluationContext{
				ChainType:     "ethereum",
				Method:        "eth_sendTransaction",
				To:            strPtr(tt.toAddress),
				Value:         big.NewInt(0),
				Timestamp:     time.Now(),
				ConditionSets: tt.conditionSets,
			}

			result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Decision != tt.expected {
				t.Errorf("expected %v, got %v (reason: %s)", tt.expected, result.Decision, result.Reason)
			}
		})
	}
}

func strPtr(s string) *string {
	return &s
}
