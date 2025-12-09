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
			name: "no_policies_denies_by_default",
			policy: nil,
			evalCtx: &EvaluationContext{
				ChainType: "ethereum",
				Method:    "eth_sendTransaction",
				Timestamp: time.Now(),
			},
			expected: DecisionDeny, // Default-deny: no policies means no explicit allow
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

// TestNestedFieldExtraction tests nested field extraction from maps
func TestNestedFieldExtraction(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Nested Field Policy",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Check nested typed data field",
					"method": "eth_signTypedData_v4",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_typed_data_message",
							"field":        "transfer.recipient",
							"operator":     "eq",
							"value":        "0xabc",
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name     string
		message  map[string]interface{}
		expected PolicyDecision
	}{
		{
			name: "nested_field_matches",
			message: map[string]interface{}{
				"transfer": map[string]interface{}{
					"recipient": "0xabc",
					"amount":    "1000",
				},
			},
			expected: DecisionAllow,
		},
		{
			name: "nested_field_does_not_match",
			message: map[string]interface{}{
				"transfer": map[string]interface{}{
					"recipient": "0xdef",
					"amount":    "1000",
				},
			},
			expected: DecisionDeny,
		},
		{
			name: "missing_nested_field",
			message: map[string]interface{}{
				"other": "value",
			},
			expected: DecisionDeny,
		},
		{
			name:     "nil_message",
			message:  nil,
			expected: DecisionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evalCtx := &EvaluationContext{
				ChainType:        "ethereum",
				Method:           "eth_signTypedData_v4",
				TypedDataMessage: tt.message,
				Timestamp:        time.Now(),
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

// TestAllOperators tests all comparison operators
func TestAllOperators(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	makePolicy := func(operator string, value interface{}) *types.Policy {
		return &types.Policy{
			ID:        uuid.New(),
			Name:      "Operator Test Policy",
			ChainType: "ethereum",
			Version:   "1.0",
			Rules: map[string]interface{}{
				"rules": []interface{}{
					map[string]interface{}{
						"name":   "Test rule",
						"method": "*",
						"action": "ALLOW",
						"conditions": []interface{}{
							map[string]interface{}{
								"field_source": "ethereum_transaction",
								"field":        "value",
								"operator":     operator,
								"value":        value,
							},
						},
					},
				},
			},
		}
	}

	tests := []struct {
		name     string
		operator string
		expected interface{}
		actual   *big.Int
		decision PolicyDecision
	}{
		// eq tests
		{"eq_matches", "eq", "100", big.NewInt(100), DecisionAllow},
		{"eq_no_match", "eq", "100", big.NewInt(200), DecisionDeny},
		// neq tests
		{"neq_different", "neq", "100", big.NewInt(200), DecisionAllow},
		{"neq_same", "neq", "100", big.NewInt(100), DecisionDeny},
		// lt tests
		{"lt_less", "lt", "100", big.NewInt(50), DecisionAllow},
		{"lt_equal", "lt", "100", big.NewInt(100), DecisionDeny},
		{"lt_greater", "lt", "100", big.NewInt(150), DecisionDeny},
		// lte tests
		{"lte_less", "lte", "100", big.NewInt(50), DecisionAllow},
		{"lte_equal", "lte", "100", big.NewInt(100), DecisionAllow},
		{"lte_greater", "lte", "100", big.NewInt(150), DecisionDeny},
		// gt tests
		{"gt_greater", "gt", "100", big.NewInt(150), DecisionAllow},
		{"gt_equal", "gt", "100", big.NewInt(100), DecisionDeny},
		{"gt_less", "gt", "100", big.NewInt(50), DecisionDeny},
		// gte tests
		{"gte_greater", "gte", "100", big.NewInt(150), DecisionAllow},
		{"gte_equal", "gte", "100", big.NewInt(100), DecisionAllow},
		{"gte_less", "gte", "100", big.NewInt(50), DecisionDeny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := makePolicy(tt.operator, tt.expected)
			evalCtx := &EvaluationContext{
				ChainType: "ethereum",
				Method:    "eth_sendTransaction",
				To:        strPtr("0x1234567890abcdef1234567890abcdef12345678"),
				Value:     tt.actual,
				Timestamp: time.Now(),
			}

			result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Decision != tt.decision {
				t.Errorf("expected %v, got %v", tt.decision, result.Decision)
			}
		})
	}
}

// TestPersonalMessageFieldSource tests the ethereum_message field source
func TestPersonalMessageFieldSource(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Personal Message Policy",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Check message content",
					"method": "personal_sign",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_message",
							"field":        "message",
							"operator":     "eq",
							"value":        "Sign in to MyApp",
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name     string
		message  string
		expected PolicyDecision
	}{
		{
			name:     "message_matches",
			message:  "Sign in to MyApp",
			expected: DecisionAllow,
		},
		{
			name:     "message_does_not_match",
			message:  "Other message",
			expected: DecisionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evalCtx := &EvaluationContext{
				ChainType:       "ethereum",
				Method:          "personal_sign",
				PersonalMessage: tt.message,
				Timestamp:       time.Now(),
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

// TestEIP7702AuthorizationFieldSource tests the ethereum_7702_authorization field source
func TestEIP7702AuthorizationFieldSource(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "EIP-7702 Policy",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Check authorization contract",
					"method": "eth_sendTransaction",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_7702_authorization",
							"field":        "contract",
							"operator":     "eq",
							"value":        "0xapprovedcontract",
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name     string
		contract string
		expected PolicyDecision
	}{
		{
			name:     "contract_matches",
			contract: "0xapprovedcontract",
			expected: DecisionAllow,
		},
		{
			name:     "contract_does_not_match",
			contract: "0xothercontract",
			expected: DecisionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evalCtx := &EvaluationContext{
				ChainType:             "ethereum",
				Method:                "eth_sendTransaction",
				AuthorizationContract: tt.contract,
				Timestamp:             time.Now(),
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

// TestDecodedCalldataFieldSource tests the ethereum_calldata field source
func TestDecodedCalldataFieldSource(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Calldata Policy",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Check ERC20 transfer recipient",
					"method": "eth_sendTransaction",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_calldata",
							"field":        "transfer.to",
							"operator":     "eq",
							"value":        "0xrecipient",
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name     string
		calldata map[string]interface{}
		expected PolicyDecision
	}{
		{
			name: "calldata_matches",
			calldata: map[string]interface{}{
				"transfer": map[string]interface{}{
					"to":     "0xrecipient",
					"amount": "1000",
				},
			},
			expected: DecisionAllow,
		},
		{
			name: "calldata_does_not_match",
			calldata: map[string]interface{}{
				"transfer": map[string]interface{}{
					"to":     "0xotherrecipient",
					"amount": "1000",
				},
			},
			expected: DecisionDeny,
		},
		{
			name:     "nil_calldata",
			calldata: nil,
			expected: DecisionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evalCtx := &EvaluationContext{
				ChainType:       "ethereum",
				Method:          "eth_sendTransaction",
				DecodedCalldata: tt.calldata,
				Timestamp:       time.Now(),
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

// TestChainTypeFiltering tests that policies are filtered by chain type
func TestChainTypeFiltering(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	ethereumPolicy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Ethereum Policy",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":       "Allow all",
					"method":     "*",
					"action":     "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "chain_id",
							"operator":     "eq",
							"value":        float64(1),
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name      string
		chainType string
		chainID   int64
		expected  PolicyDecision
	}{
		{
			name:      "matching_chain_type",
			chainType: "ethereum",
			chainID:   1,
			expected:  DecisionAllow,
		},
		{
			name:      "different_chain_type_skipped",
			chainType: "solana",
			chainID:   1,
			expected:  DecisionDeny, // No matching policy
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evalCtx := &EvaluationContext{
				ChainType: tt.chainType,
				ChainID:   tt.chainID,
				Method:    "eth_sendTransaction",
				To:        strPtr("0x1234"),
				Value:     big.NewInt(0),
				Timestamp: time.Now(),
			}

			result, err := engine.Evaluate(ctx, []*types.Policy{ethereumPolicy}, evalCtx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Decision != tt.expected {
				t.Errorf("expected %v, got %v (reason: %s)", tt.expected, result.Decision, result.Reason)
			}
		})
	}
}

// TestMultipleConditionsANDLogic tests that multiple conditions use AND logic
func TestMultipleConditionsANDLogic(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Multi-condition Policy",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Allow small transfers to approved address",
					"method": "*",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "to",
							"operator":     "eq",
							"value":        "0xapprovedaddress",
						},
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "value",
							"operator":     "lte",
							"value":        "1000",
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name     string
		to       string
		value    *big.Int
		expected PolicyDecision
	}{
		{
			name:     "both_conditions_match",
			to:       "0xapprovedaddress",
			value:    big.NewInt(500),
			expected: DecisionAllow,
		},
		{
			name:     "first_condition_fails",
			to:       "0xotheraddress",
			value:    big.NewInt(500),
			expected: DecisionDeny,
		},
		{
			name:     "second_condition_fails",
			to:       "0xapprovedaddress",
			value:    big.NewInt(2000),
			expected: DecisionDeny,
		},
		{
			name:     "both_conditions_fail",
			to:       "0xotheraddress",
			value:    big.NewInt(2000),
			expected: DecisionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evalCtx := &EvaluationContext{
				ChainType: "ethereum",
				Method:    "eth_sendTransaction",
				To:        strPtr(tt.to),
				Value:     tt.value,
				Timestamp: time.Now(),
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

// TestNewEngine tests engine creation
func TestNewEngine(t *testing.T) {
	engine := NewEngine()
	if engine == nil {
		t.Error("NewEngine() returned nil")
	}
}

// TestPolicyDecisionConstants tests decision constants
func TestPolicyDecisionConstants(t *testing.T) {
	if DecisionDeny != 0 {
		t.Error("DecisionDeny should be 0")
	}
	if DecisionAllow != 1 {
		t.Error("DecisionAllow should be 1")
	}
}

// TestEthereumTransactionDataField tests the 'data' field from ethereum transactions
func TestEthereumTransactionDataField(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Data Field Policy",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Check transaction data",
					"method": "*",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "data",
							"operator":     "eq",
							"value":        "68656c6c6f",
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name     string
		data     []byte
		expected PolicyDecision
	}{
		{
			name:     "data_matches",
			data:     []byte("hello"),
			expected: DecisionAllow,
		},
		{
			name:     "data_does_not_match",
			data:     []byte("world"),
			expected: DecisionDeny,
		},
		{
			name:     "nil_data",
			data:     nil,
			expected: DecisionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evalCtx := &EvaluationContext{
				ChainType: "ethereum",
				Method:    "eth_sendTransaction",
				To:        strPtr("0x1234"),
				Data:      tt.data,
				Timestamp: time.Now(),
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

// TestEthereumTransactionFromField tests the 'from' field
func TestEthereumTransactionFromField(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "From Field Policy",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Check from address",
					"method": "*",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "from",
							"operator":     "eq",
							"value":        "0xsenderaddress",
						},
					},
				},
			},
		},
	}

	evalCtx := &EvaluationContext{
		ChainType: "ethereum",
		Method:    "eth_sendTransaction",
		Address:   "0xSENDERADDRESS", // uppercase
		To:        strPtr("0x1234"),
		Timestamp: time.Now(),
	}

	result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should match (case-insensitive)
	if result.Decision != DecisionAllow {
		t.Errorf("expected allow, got deny (reason: %s)", result.Reason)
	}
}

// TestSystemFieldTimestamp tests the system timestamp field
func TestSystemFieldTimestamp(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Timestamp Policy",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Check timestamp",
					"method": "*",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "system",
							"field":        "current_unix_timestamp",
							"operator":     "gt",
							"value":        float64(0),
						},
					},
				},
			},
		},
	}

	evalCtx := &EvaluationContext{
		ChainType: "ethereum",
		Method:    "eth_sendTransaction",
		To:        strPtr("0x1234"),
		Timestamp: time.Now(),
	}

	result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Decision != DecisionAllow {
		t.Errorf("expected allow, got deny (reason: %s)", result.Reason)
	}
}

// TestSystemFieldUnknown tests an unknown system field
func TestSystemFieldUnknown(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Unknown System Field Policy",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Check unknown field",
					"method": "*",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "system",
							"field":        "unknown_field",
							"operator":     "eq",
							"value":        "anything",
						},
					},
				},
			},
		},
	}

	evalCtx := &EvaluationContext{
		ChainType: "ethereum",
		Method:    "eth_sendTransaction",
		To:        strPtr("0x1234"),
		Timestamp: time.Now(),
	}

	result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Unknown field should not match, resulting in deny
	if result.Decision != DecisionDeny {
		t.Errorf("expected deny for unknown field, got allow")
	}
}

// TestInOperatorWithStringArray tests the 'in' operator with []string
func TestInOperatorWithStringArray(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "In Operator Policy",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Check address in list",
					"method": "*",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "to",
							"operator":     "in",
							"value":        []string{"0xaddr1", "0xaddr2", "0xaddr3"},
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name     string
		to       string
		expected PolicyDecision
	}{
		{"in_list", "0xaddr2", DecisionAllow},
		{"not_in_list", "0xother", DecisionDeny},
		{"case_insensitive", "0xADDR1", DecisionAllow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evalCtx := &EvaluationContext{
				ChainType: "ethereum",
				Method:    "eth_sendTransaction",
				To:        strPtr(tt.to),
				Timestamp: time.Now(),
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

// TestToBigIntConversions tests various type conversions to big.Int
func TestToBigIntConversions(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	// Test different expected value types in policy conditions
	makePolicy := func(value interface{}) *types.Policy {
		return &types.Policy{
			ID:        uuid.New(),
			Name:      "BigInt Test Policy",
			ChainType: "ethereum",
			Version:   "1.0",
			Rules: map[string]interface{}{
				"rules": []interface{}{
					map[string]interface{}{
						"name":   "Test rule",
						"method": "*",
						"action": "ALLOW",
						"conditions": []interface{}{
							map[string]interface{}{
								"field_source": "ethereum_transaction",
								"field":        "value",
								"operator":     "lte",
								"value":        value,
							},
						},
					},
				},
			},
		}
	}

	tests := []struct {
		name         string
		policyValue  interface{}
		actualValue  *big.Int
		expected     PolicyDecision
	}{
		{"string_value", "1000", big.NewInt(500), DecisionAllow},
		{"float64_value", float64(1000), big.NewInt(500), DecisionAllow},
		{"int_value", int(1000), big.NewInt(500), DecisionAllow},
		{"int64_value", int64(1000), big.NewInt(500), DecisionAllow},
		{"big_int_pointer", big.NewInt(1000), big.NewInt(500), DecisionAllow},
		{"hex_string", "0x3e8", big.NewInt(500), DecisionAllow}, // 0x3e8 = 1000
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := makePolicy(tt.policyValue)
			evalCtx := &EvaluationContext{
				ChainType: "ethereum",
				Method:    "eth_sendTransaction",
				To:        strPtr("0x1234"),
				Value:     tt.actualValue,
				Timestamp: time.Now(),
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

// TestWildcardChainType tests that wildcard chain type matches any chain
func TestWildcardChainType(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Wildcard Chain Policy",
		ChainType: "*",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Allow all chains",
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
	}

	tests := []struct {
		chainType string
		expected  PolicyDecision
	}{
		{"ethereum", DecisionAllow},
		{"polygon", DecisionAllow},
		{"arbitrum", DecisionAllow},
	}

	for _, tt := range tests {
		t.Run(tt.chainType, func(t *testing.T) {
			evalCtx := &EvaluationContext{
				ChainType: tt.chainType,
				Method:    "eth_sendTransaction",
				To:        strPtr("0x1234"),
				Timestamp: time.Now(),
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

// TestParsePolicySchemaErrors tests error handling in parsePolicySchema
func TestParsePolicySchemaErrors(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	tests := []struct {
		name     string
		policy   *types.Policy
		expected PolicyDecision
	}{
		{
			name: "rules_not_array",
			policy: &types.Policy{
				ID:        uuid.New(),
				Name:      "Invalid Policy",
				ChainType: "ethereum",
				Version:   "1.0",
				Rules: map[string]interface{}{
					"rules": "not an array",
				},
			},
			expected: DecisionDeny, // Should deny due to no valid rules
		},
		{
			name: "rule_not_map",
			policy: &types.Policy{
				ID:        uuid.New(),
				Name:      "Invalid Policy",
				ChainType: "ethereum",
				Version:   "1.0",
				Rules: map[string]interface{}{
					"rules": []interface{}{
						"not a map",
					},
				},
			},
			expected: DecisionDeny,
		},
		{
			name: "conditions_not_array",
			policy: &types.Policy{
				ID:        uuid.New(),
				Name:      "Invalid Policy",
				ChainType: "ethereum",
				Version:   "1.0",
				Rules: map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"name":       "Test",
							"method":     "*",
							"action":     "ALLOW",
							"conditions": "not an array",
						},
					},
				},
			},
			expected: DecisionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evalCtx := &EvaluationContext{
				ChainType: "ethereum",
				Method:    "eth_sendTransaction",
				To:        strPtr("0x1234"),
				Timestamp: time.Now(),
			}

			result, err := engine.Evaluate(ctx, []*types.Policy{tt.policy}, evalCtx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Decision != tt.expected {
				t.Errorf("expected %v, got %v (reason: %s)", tt.expected, result.Decision, result.Reason)
			}
		})
	}
}

// TestNilToValue tests nil 'to' address in transaction
func TestNilToValue(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Nil To Policy",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Check to address",
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
	}

	evalCtx := &EvaluationContext{
		ChainType: "ethereum",
		Method:    "eth_sendTransaction",
		To:        nil, // Contract creation has nil 'to'
		Timestamp: time.Now(),
	}

	result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Nil 'to' should not match
	if result.Decision != DecisionDeny {
		t.Errorf("expected deny for nil 'to', got allow")
	}
}

// TestNilValueField tests nil 'value' in transaction
func TestNilValueField(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Nil Value Policy",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Check value",
					"method": "*",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "value",
							"operator":     "lte",
							"value":        "1000",
						},
					},
				},
			},
		},
	}

	evalCtx := &EvaluationContext{
		ChainType: "ethereum",
		Method:    "eth_sendTransaction",
		To:        strPtr("0x1234"),
		Value:     nil,
		Timestamp: time.Now(),
	}

	result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Nil value should not match
	if result.Decision != DecisionDeny {
		t.Errorf("expected deny for nil value, got allow")
	}
}

// TestAddressCaseInsensitivity tests that address comparison is case-insensitive
func TestAddressCaseInsensitivity(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Case Test Policy",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Allow address",
					"method": "*",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "to",
							"operator":     "eq",
							"value":        "0xABCdef1234567890ABCDEF1234567890abcdef12",
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name     string
		to       string
		expected PolicyDecision
	}{
		{
			name:     "lowercase_matches",
			to:       "0xabcdef1234567890abcdef1234567890abcdef12",
			expected: DecisionAllow,
		},
		{
			name:     "uppercase_matches",
			to:       "0xABCDEF1234567890ABCDEF1234567890ABCDEF12",
			expected: DecisionAllow,
		},
		{
			name:     "mixed_case_matches",
			to:       "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12",
			expected: DecisionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evalCtx := &EvaluationContext{
				ChainType: "ethereum",
				Method:    "eth_sendTransaction",
				To:        strPtr(tt.to),
				Value:     big.NewInt(0),
				Timestamp: time.Now(),
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

// TestToBigIntJsonNumber tests json.Number type conversion
func TestToBigIntJsonNumber(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	// Create a policy with numeric comparison
	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Value Check",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Check value",
					"method": "*",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "value",
							"operator":     "lte",
							"value":        "1000000000000000000", // 1 ETH
						},
					},
				},
			},
		},
	}

	evalCtx := &EvaluationContext{
		ChainType: "ethereum",
		Method:    "eth_sendTransaction",
		To:        strPtr("0x1234567890123456789012345678901234567890"),
		Value:     big.NewInt(500000000000000000), // 0.5 ETH
		Timestamp: time.Now(),
	}

	result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Decision != DecisionAllow {
		t.Errorf("expected allow, got %v", result.Decision)
	}
}

// TestToBigIntInvalidString tests that invalid strings in toBigInt comparison result in DENY
func TestToBigIntInvalidString(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	// Policy with invalid string value for comparison
	// When value can't be converted to big.Int, comparison returns false
	// Condition doesn't match, so default-deny applies
	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Invalid Value Check",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Check value",
					"method": "*",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "value",
							"operator":     "lte",
							"value":        "not_a_number", // Invalid string
						},
					},
				},
			},
		},
	}

	evalCtx := &EvaluationContext{
		ChainType: "ethereum",
		Method:    "eth_sendTransaction",
		To:        strPtr("0x1234567890123456789012345678901234567890"),
		Value:     big.NewInt(100),
		Timestamp: time.Now(),
	}

	result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// When expected value can't be converted, compareBigInt returns ok=false
	// Condition doesn't match, default-deny applies
	if result.Decision != DecisionDeny {
		t.Errorf("expected deny (invalid comparison should not match), got %v", result.Decision)
	}
}

// TestCompareBigIntWithNilValues tests compareBigInt behavior with nil conversion
func TestCompareBigIntWithNilValues(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	// Use a boolean which can't be converted to big.Int
	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Bool Check",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Invalid compare",
					"method": "*",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "value",
							"operator":     "gt",
							"value":        true, // boolean - can't convert to big.Int
						},
					},
				},
			},
		},
	}

	evalCtx := &EvaluationContext{
		ChainType: "ethereum",
		Method:    "eth_sendTransaction",
		To:        strPtr("0x1234567890123456789012345678901234567890"),
		Value:     big.NewInt(100),
		Timestamp: time.Now(),
	}

	result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// compareBigInt returns 0 when conversion fails, so gt returns false
	// Condition doesn't match, rule doesn't apply, default deny
	if result.Decision != DecisionDeny {
		t.Errorf("expected deny, got %v", result.Decision)
	}
}

// TestParseRuleWithNonMapCondition tests parseRule when condition is not a map
// Non-map conditions are silently skipped in parseRule
func TestParseRuleWithNonMapCondition(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	// Policy with ONLY a non-map condition (all conditions skipped = rule has no conditions)
	// When a rule has no conditions, it doesn't match any request
	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Bad Condition Only",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Skips bad condition",
					"method": "*",
					"action": "ALLOW",
					"conditions": []interface{}{
						"not_a_map", // This is not a map - will be skipped
					},
				},
			},
		},
	}

	evalCtx := &EvaluationContext{
		ChainType: "ethereum",
		Method:    "eth_sendTransaction",
		To:        strPtr("0x1234567890123456789012345678901234567890"),
		Value:     big.NewInt(0),
		Timestamp: time.Now(),
	}

	result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Non-map condition is skipped, leaving rule with no conditions
	// A rule with no parsed conditions still evaluates (vacuously true)
	// Result depends on implementation - test documents actual behavior
	// Current behavior: returns DENY (no rules match)
	if result.Decision != DecisionDeny {
		t.Errorf("expected deny, got %v", result.Decision)
	}
}

// TestValidateConditionMissingField tests validation error for missing 'field'
func TestValidateConditionMissingField(t *testing.T) {
	engine := NewEngine()

	policy := &types.Policy{
		Name:      "Missing Field",
		ChainType: "ethereum",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"method": "eth_sendTransaction",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							// "field" is missing
							"operator": "eq",
							"value":    "0x123",
						},
					},
				},
			},
		},
	}

	err := engine.ValidatePolicy(policy)
	if err == nil {
		t.Error("expected error for missing 'field'")
	}
	if !strings.Contains(err.Error(), "missing 'field'") {
		t.Errorf("expected error about missing 'field', got: %v", err)
	}
}

// TestValidateConditionMissingValue tests validation error for missing 'value'
func TestValidateConditionMissingValue(t *testing.T) {
	engine := NewEngine()

	policy := &types.Policy{
		Name:      "Missing Value",
		ChainType: "ethereum",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"method": "eth_sendTransaction",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "to",
							"operator":     "eq",
							// "value" is missing
						},
					},
				},
			},
		},
	}

	err := engine.ValidatePolicy(policy)
	if err == nil {
		t.Error("expected error for missing 'value'")
	}
	if !strings.Contains(err.Error(), "missing 'value'") {
		t.Errorf("expected error about missing 'value', got: %v", err)
	}
}

// TestValidateConditionMissingOperator tests validation error for missing 'operator'
func TestValidateConditionMissingOperator(t *testing.T) {
	engine := NewEngine()

	policy := &types.Policy{
		Name:      "Missing Operator",
		ChainType: "ethereum",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"method": "eth_sendTransaction",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "to",
							// "operator" is missing
							"value": "0x123",
						},
					},
				},
			},
		},
	}

	err := engine.ValidatePolicy(policy)
	if err == nil {
		t.Error("expected error for missing 'operator'")
	}
	if !strings.Contains(err.Error(), "missing 'operator'") {
		t.Errorf("expected error about missing 'operator', got: %v", err)
	}
}

// TestValidateConditionNotValidObject tests validation error when condition is not a valid object
func TestValidateConditionNotValidObject(t *testing.T) {
	engine := NewEngine()

	policy := &types.Policy{
		Name:      "Invalid Condition Object",
		ChainType: "ethereum",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"method": "eth_sendTransaction",
					"action": "ALLOW",
					"conditions": []interface{}{
						123, // Not a valid object (int instead of map)
					},
				},
			},
		},
	}

	err := engine.ValidatePolicy(policy)
	if err == nil {
		t.Error("expected error for invalid condition object")
	}
	if !strings.Contains(err.Error(), "not a valid object") {
		t.Errorf("expected error about invalid object, got: %v", err)
	}
}

// TestUnknownOperatorReturnsNoMatch tests that unknown operators don't match
func TestUnknownOperatorReturnsNoMatch(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Unknown Operator",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Unknown op",
					"method": "*",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "to",
							"operator":     "unknown_op", // Invalid operator
							"value":        "0x1234567890123456789012345678901234567890",
						},
					},
				},
			},
		},
	}

	evalCtx := &EvaluationContext{
		ChainType: "ethereum",
		Method:    "eth_sendTransaction",
		To:        strPtr("0x1234567890123456789012345678901234567890"),
		Value:     big.NewInt(0),
		Timestamp: time.Now(),
	}

	result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Unknown operator returns false in compareValues, so condition doesn't match
	if result.Decision != DecisionDeny {
		t.Errorf("expected deny (unknown operator), got %v", result.Decision)
	}
}

// TestMethodWildcardMatching tests that "*" method matches all methods
func TestMethodWildcardMatching(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Wildcard Method",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Wildcard method",
					"method": "*", // Wildcard
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "to",
							"operator":     "eq",
							"value":        "0x1234567890123456789012345678901234567890",
						},
					},
				},
			},
		},
	}

	methods := []string{"eth_sendTransaction", "eth_signTypedData", "personal_sign", "custom_method"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			evalCtx := &EvaluationContext{
				ChainType: "ethereum",
				Method:    method,
				To:        strPtr("0x1234567890123456789012345678901234567890"),
				Value:     big.NewInt(0),
				Timestamp: time.Now(),
			}

			result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Decision != DecisionAllow {
				t.Errorf("expected allow for method %s, got %v", method, result.Decision)
			}
		})
	}
}

// TestMethodSpecificNotMatching tests that specific method doesn't match other methods
func TestMethodSpecificNotMatching(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Specific Method",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Specific method",
					"method": "eth_sendTransaction", // Only matches this specific method
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "to",
							"operator":     "eq",
							"value":        "0x1234567890123456789012345678901234567890",
						},
					},
				},
			},
		},
	}

	// Should not match eth_signTypedData
	evalCtx := &EvaluationContext{
		ChainType: "ethereum",
		Method:    "eth_signTypedData",
		To:        strPtr("0x1234567890123456789012345678901234567890"),
		Value:     big.NewInt(0),
		Timestamp: time.Now(),
	}

	result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Method doesn't match, so rule doesn't apply, default deny
	if result.Decision != DecisionDeny {
		t.Errorf("expected deny (method doesn't match), got %v", result.Decision)
	}
}

// TestMissingMethodDefaultsToWildcard tests that missing method defaults to "*"
func TestMissingMethodDefaultsToWildcard(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	// Policy without explicit "method" field
	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "No Method Specified",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name": "No method",
					// "method" is missing - defaults to "*"
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "to",
							"operator":     "eq",
							"value":        "0x1234567890123456789012345678901234567890",
						},
					},
				},
			},
		},
	}

	evalCtx := &EvaluationContext{
		ChainType: "ethereum",
		Method:    "any_method",
		To:        strPtr("0x1234567890123456789012345678901234567890"),
		Value:     big.NewInt(0),
		Timestamp: time.Now(),
	}

	result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Missing method defaults to "*", so should match
	if result.Decision != DecisionAllow {
		t.Errorf("expected allow (default wildcard method), got %v", result.Decision)
	}
}

// TestMissingActionDefaultsToDeny tests that missing action defaults to "DENY"
func TestMissingActionDefaultsToDeny(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	// Policy without explicit "action" field
	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "No Action Specified",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "No action",
					"method": "*",
					// "action" is missing - defaults to DENY
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "to",
							"operator":     "eq",
							"value":        "0x1234567890123456789012345678901234567890",
						},
					},
				},
			},
		},
	}

	evalCtx := &EvaluationContext{
		ChainType: "ethereum",
		Method:    "eth_sendTransaction",
		To:        strPtr("0x1234567890123456789012345678901234567890"),
		Value:     big.NewInt(0),
		Timestamp: time.Now(),
	}

	result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Missing action defaults to DENY
	if result.Decision != DecisionDeny {
		t.Errorf("expected deny (default action), got %v", result.Decision)
	}
}

// TestUnknownFieldSourceReturnsNil tests unknown field_source returns nil
func TestUnknownFieldSourceReturnsNil(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Unknown Field Source",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Unknown source",
					"method": "*",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "unknown_source", // Invalid field source
							"field":        "something",
							"operator":     "eq",
							"value":        "test",
						},
					},
				},
			},
		},
	}

	evalCtx := &EvaluationContext{
		ChainType: "ethereum",
		Method:    "eth_sendTransaction",
		To:        strPtr("0x1234567890123456789012345678901234567890"),
		Value:     big.NewInt(0),
		Timestamp: time.Now(),
	}

	result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Unknown field source returns nil, condition doesn't match
	if result.Decision != DecisionDeny {
		t.Errorf("expected deny (unknown field source), got %v", result.Decision)
	}
}

// TestEmptyConditionsArray tests rule with empty conditions array behavior
func TestEmptyConditionsArray(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Empty Conditions",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":       "No conditions",
					"method":    "*",
					"action":    "ALLOW",
					"conditions": []interface{}{}, // Empty conditions array
				},
			},
		},
	}

	evalCtx := &EvaluationContext{
		ChainType: "ethereum",
		Method:    "eth_sendTransaction",
		To:        strPtr("0x1234567890123456789012345678901234567890"),
		Value:     big.NewInt(0),
		Timestamp: time.Now(),
	}

	result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Empty conditions array means "no restrictions" - rule matches all requests
	// This is the intended behavior for catch-all rules
	if result.Decision != DecisionAllow {
		t.Errorf("expected allow (empty conditions matches all), got %v", result.Decision)
	}
}

// TestNilCalldataField tests accessing calldata field when Calldata is nil
func TestNilCalldataField(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Calldata Check",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Calldata",
					"method": "*",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_calldata",
							"field":        "function",
							"operator":     "eq",
							"value":        "transfer",
						},
					},
				},
			},
		},
	}

	evalCtx := &EvaluationContext{
		ChainType:       "ethereum",
		Method:          "eth_sendTransaction",
		To:              strPtr("0x1234567890123456789012345678901234567890"),
		Value:           big.NewInt(0),
		DecodedCalldata: nil, // Nil calldata
		Timestamp:       time.Now(),
	}

	result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Nil calldata returns nil, condition doesn't match
	if result.Decision != DecisionDeny {
		t.Errorf("expected deny (nil calldata), got %v", result.Decision)
	}
}

// TestMultipleRulesFirstMatch tests that first matching rule wins
func TestMultipleRulesFirstMatch(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Multiple Rules",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "First Rule - DENY",
					"method": "*",
					"action": "DENY",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "to",
							"operator":     "eq",
							"value":        "0x1234567890123456789012345678901234567890",
						},
					},
				},
				map[string]interface{}{
					"name":   "Second Rule - ALLOW",
					"method": "*",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "to",
							"operator":     "eq",
							"value":        "0x1234567890123456789012345678901234567890",
						},
					},
				},
			},
		},
	}

	evalCtx := &EvaluationContext{
		ChainType: "ethereum",
		Method:    "eth_sendTransaction",
		To:        strPtr("0x1234567890123456789012345678901234567890"),
		Value:     big.NewInt(0),
		Timestamp: time.Now(),
	}

	result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First rule matches first, so DENY
	if result.Decision != DecisionDeny {
		t.Errorf("expected deny (first rule wins), got %v", result.Decision)
	}
}

// TestValuesEqualNonAddresses tests non-address value comparison
func TestValuesEqualNonAddresses(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "String Compare",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "String equality",
					"method": "*",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_typed_data_domain",
							"field":        "name",
							"operator":     "eq",
							"value":        "MyDApp",
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name     string
		domain   map[string]interface{}
		expected PolicyDecision
	}{
		{
			name:     "exact_match",
			domain:   map[string]interface{}{"name": "MyDApp"},
			expected: DecisionAllow,
		},
		{
			name:     "case_sensitive_no_match",
			domain:   map[string]interface{}{"name": "mydapp"},
			expected: DecisionDeny,
		},
		{
			name:     "different_value",
			domain:   map[string]interface{}{"name": "OtherDApp"},
			expected: DecisionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evalCtx := &EvaluationContext{
				ChainType:       "ethereum",
				Method:          "eth_signTypedData",
				TypedDataDomain: tt.domain,
				Timestamp:       time.Now(),
			}

			result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Decision != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result.Decision)
			}
		})
	}
}

// =============================================================================
// Edge Case Tests - Security-critical boundary conditions
// =============================================================================

func TestCompareBigInt_InvalidInput(t *testing.T) {
	engine := NewEngine()

	testCases := []struct {
		name     string
		actual   interface{}
		expected interface{}
	}{
		{
			name:     "invalid_string_vs_valid_number",
			actual:   "not_a_number",
			expected: "1000000000000000000",
		},
		{
			name:     "empty_string_vs_valid_number",
			actual:   "",
			expected: "1000000000000000000",
		},
		{
			name:     "only_0x_prefix",
			actual:   "0x",
			expected: "1000000000000000000",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := engine.compareBigInt(tc.actual, tc.expected)
			if ok {
				t.Errorf("compareBigInt should return ok=false for invalid input '%v'", tc.actual)
			}
		})
	}
}

func TestToBigInt_EdgeCases(t *testing.T) {
	engine := NewEngine()

	testCases := []struct {
		name        string
		input       interface{}
		expectNil   bool
		expectValue *big.Int
	}{
		{"empty_string", "", true, nil},
		{"only_0x_prefix", "0x", true, nil},
		{"invalid_hex", "0xGGGG", true, nil},
		{"valid_decimal", "1000000000000000000", false, big.NewInt(1000000000000000000)},
		{"valid_hex", "0xde0b6b3a7640000", false, nil},
		{"negative_number", "-1", false, nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := engine.toBigInt(tc.input)
			if tc.expectNil && result != nil {
				t.Errorf("expected nil for input %v, got %v", tc.input, result)
			}
			if !tc.expectNil && result == nil {
				t.Errorf("expected non-nil for input %v", tc.input)
			}
			if tc.expectValue != nil && result != nil && result.Cmp(tc.expectValue) != 0 {
				t.Errorf("value mismatch: expected %v, got %v", tc.expectValue, result)
			}
		})
	}
}

func TestPolicyEvaluation_NilValueShouldDeny(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Limit to 1 ETH",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Limit value",
					"method": "eth_sendTransaction",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "value",
							"operator":     "lte",
							"value":        "1000000000000000000",
						},
					},
				},
			},
		},
	}

	evalCtx := &EvaluationContext{
		Method:    "eth_sendTransaction",
		ChainType: "ethereum",
		Value:     nil,
		Timestamp: time.Now(),
	}

	result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Decision != DecisionDeny {
		t.Errorf("nil value should result in DENY, got %v", result.Decision)
	}
}

func TestAddressComparison_CaseSensitivity(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	targetAddr := "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Allow USDC",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Allow USDC",
					"method": "eth_sendTransaction",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "to",
							"operator":     "eq",
							"value":        targetAddr,
						},
					},
				},
			},
		},
	}

	testCases := []struct {
		name   string
		toAddr string
	}{
		{"exact_match", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},
		{"lowercase", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"},
		{"uppercase", "0xA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			evalCtx := &EvaluationContext{
				Method:    "eth_sendTransaction",
				ChainType: "ethereum",
				To:        strPtr(tc.toAddr),
				Value:     big.NewInt(0),
				Timestamp: time.Now(),
			}

			result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Decision != DecisionAllow {
				t.Errorf("address %s should match (case-insensitive), got %v", tc.toAddr, result.Decision)
			}
		})
	}
}

func TestPolicyWithNilTo_ContractCreation(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Block and Allow",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Block attacker",
					"method": "eth_sendTransaction",
					"action": "DENY",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "to",
							"operator":     "eq",
							"value":        "0xBAD0000000000000000000000000000000000BAD",
						},
					},
				},
				map[string]interface{}{
					"name":   "Allow others",
					"method": "*",
					"action": "ALLOW",
				},
			},
		},
	}

	evalCtx := &EvaluationContext{
		Method:    "eth_sendTransaction",
		ChainType: "ethereum",
		To:        nil, // Contract creation
		Value:     big.NewInt(0),
		Timestamp: time.Now(),
	}

	result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Decision != DecisionAllow {
		t.Errorf("nil To should not match address condition, should allow, got %v", result.Decision)
	}
}

func TestBigIntOverflow_Uint256Max(t *testing.T) {
	engine := NewEngine()
	ctx := context.Background()

	maxUint256 := "115792089237316195423570985008687907853269984665640564039457584007913129639935"

	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      "Max uint256",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Allow up to max",
					"method": "eth_sendTransaction",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "value",
							"operator":     "lte",
							"value":        maxUint256,
						},
					},
				},
			},
		},
	}

	largeValue := new(big.Int)
	largeValue.SetString("115792089237316195423570985008687907853269984665640564039457584007913129639934", 10)

	evalCtx := &EvaluationContext{
		Method:    "eth_sendTransaction",
		ChainType: "ethereum",
		Value:     largeValue,
		Timestamp: time.Now(),
	}

	result, err := engine.Evaluate(ctx, []*types.Policy{policy}, evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Decision != DecisionAllow {
		t.Errorf("large value within limit should be allowed, got %v", result.Decision)
	}
}
