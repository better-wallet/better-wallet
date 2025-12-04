package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPolicyVersion(t *testing.T) {
	assert.Equal(t, "1.0", PolicyVersion)
}

func TestFieldSourceConstants(t *testing.T) {
	assert.Equal(t, FieldSource("ethereum_transaction"), FieldSourceEthereumTransaction)
	assert.Equal(t, FieldSource("ethereum_calldata"), FieldSourceEthereumCalldata)
	assert.Equal(t, FieldSource("ethereum_typed_data_domain"), FieldSourceEthereumTypedDataDomain)
	assert.Equal(t, FieldSource("ethereum_typed_data_message"), FieldSourceEthereumTypedDataMessage)
	assert.Equal(t, FieldSource("ethereum_7702_authorization"), FieldSourceEthereum7702Authorization)
	assert.Equal(t, FieldSource("ethereum_message"), FieldSourceEthereumMessage)
	assert.Equal(t, FieldSource("system"), FieldSourceSystem)
}

func TestConditionOperatorConstants(t *testing.T) {
	assert.Equal(t, ConditionOperator("eq"), OperatorEq)
	assert.Equal(t, ConditionOperator("neq"), OperatorNeq)
	assert.Equal(t, ConditionOperator("lt"), OperatorLt)
	assert.Equal(t, ConditionOperator("lte"), OperatorLte)
	assert.Equal(t, ConditionOperator("gt"), OperatorGt)
	assert.Equal(t, ConditionOperator("gte"), OperatorGte)
	assert.Equal(t, ConditionOperator("in"), OperatorIn)
	assert.Equal(t, ConditionOperator("in_condition_set"), OperatorInConditionSet)
}

func TestRuleActionConstants(t *testing.T) {
	assert.Equal(t, RuleAction("ALLOW"), ActionAllow)
	assert.Equal(t, RuleAction("DENY"), ActionDeny)
}

func TestEthereumTransactionFields(t *testing.T) {
	// Verify all expected fields are present
	expectedFields := []string{"to", "value", "from", "data"}
	for _, field := range expectedFields {
		_, exists := EthereumTransactionFields[field]
		assert.True(t, exists, "expected field %s to exist", field)
	}
	assert.Len(t, EthereumTransactionFields, len(expectedFields))
}

func TestEthereumCalldataFields(t *testing.T) {
	// Verify ERC20 fields are present
	expectedFields := []string{
		"transfer.to",
		"transfer.amount",
		"approve.spender",
		"approve.amount",
	}
	for _, field := range expectedFields {
		_, exists := EthereumCalldataFields[field]
		assert.True(t, exists, "expected field %s to exist", field)
	}
}

func TestEthereumTypedDataDomainFields(t *testing.T) {
	expectedFields := []string{
		"chainId",
		"verifyingContract",
		"name",
		"version",
	}
	for _, field := range expectedFields {
		_, exists := EthereumTypedDataDomainFields[field]
		assert.True(t, exists, "expected field %s to exist", field)
	}
	assert.Len(t, EthereumTypedDataDomainFields, len(expectedFields))
}

func TestSystemFields(t *testing.T) {
	_, exists := SystemFields["current_unix_timestamp"]
	assert.True(t, exists, "expected current_unix_timestamp field to exist")
}

func TestPolicyConditionStruct(t *testing.T) {
	condition := PolicyCondition{
		FieldSource: FieldSourceEthereumTransaction,
		Field:       "to",
		Operator:    OperatorEq,
		Value:       "0x742d35cc6634c0532925a3b844bc454e4438f44e",
	}

	assert.Equal(t, FieldSourceEthereumTransaction, condition.FieldSource)
	assert.Equal(t, "to", condition.Field)
	assert.Equal(t, OperatorEq, condition.Operator)
	assert.Equal(t, "0x742d35cc6634c0532925a3b844bc454e4438f44e", condition.Value)
}

func TestPolicyRuleStruct(t *testing.T) {
	rule := PolicyRule{
		Name:   "Allow transfers to whitelist",
		Method: "eth_sendTransaction",
		Conditions: []PolicyCondition{
			{
				FieldSource: FieldSourceEthereumTransaction,
				Field:       "to",
				Operator:    OperatorIn,
				Value:       []string{"0x123", "0x456"},
			},
		},
		Action: ActionAllow,
	}

	assert.Equal(t, "Allow transfers to whitelist", rule.Name)
	assert.Equal(t, "eth_sendTransaction", rule.Method)
	assert.Len(t, rule.Conditions, 1)
	assert.Equal(t, ActionAllow, rule.Action)
}

func TestPolicySchemaStruct(t *testing.T) {
	schema := PolicySchema{
		Version:   PolicyVersion,
		Name:      "Default Policy",
		ChainType: ChainTypeEthereum,
		Rules: []PolicyRule{
			{
				Name:       "Allow all",
				Method:     "*",
				Conditions: []PolicyCondition{},
				Action:     ActionAllow,
			},
		},
	}

	assert.Equal(t, "1.0", schema.Version)
	assert.Equal(t, "Default Policy", schema.Name)
	assert.Equal(t, ChainTypeEthereum, schema.ChainType)
	assert.Len(t, schema.Rules, 1)
}

func TestPolicyConditionWithInConditionSet(t *testing.T) {
	condition := PolicyCondition{
		FieldSource: FieldSourceEthereumTransaction,
		Field:       "to",
		Operator:    OperatorInConditionSet,
		Value:       "allowed-addresses-set",
	}

	assert.Equal(t, OperatorInConditionSet, condition.Operator)
	assert.Equal(t, "allowed-addresses-set", condition.Value)
}

func TestPolicyConditionWithNumericComparison(t *testing.T) {
	// Test value comparison operators
	tests := []struct {
		name     string
		operator ConditionOperator
		value    interface{}
	}{
		{
			name:     "greater than",
			operator: OperatorGt,
			value:    1000000000000000000, // 1 ETH in wei
		},
		{
			name:     "less than or equal",
			operator: OperatorLte,
			value:    "10000000000000000000", // 10 ETH as string
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			condition := PolicyCondition{
				FieldSource: FieldSourceEthereumTransaction,
				Field:       "value",
				Operator:    tt.operator,
				Value:       tt.value,
			}

			assert.Equal(t, FieldSourceEthereumTransaction, condition.FieldSource)
			assert.Equal(t, "value", condition.Field)
			assert.Equal(t, tt.operator, condition.Operator)
			assert.Equal(t, tt.value, condition.Value)
		})
	}
}
