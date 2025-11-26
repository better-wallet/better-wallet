package types

// PolicyVersion is the current policy schema version
const PolicyVersion = "1.0"

// FieldSource represents the data source for policy condition evaluation
type FieldSource string

const (
	// FieldSourceEthereumTransaction evaluates against raw transaction parameters
	FieldSourceEthereumTransaction FieldSource = "ethereum_transaction"
	// FieldSourceEthereumCalldata evaluates against decoded function call data
	FieldSourceEthereumCalldata FieldSource = "ethereum_calldata"
	// FieldSourceEthereumTypedDataDomain evaluates against EIP-712 domain fields
	FieldSourceEthereumTypedDataDomain FieldSource = "ethereum_typed_data_domain"
	// FieldSourceEthereumTypedDataMessage evaluates against EIP-712 message fields
	FieldSourceEthereumTypedDataMessage FieldSource = "ethereum_typed_data_message"
	// FieldSourceEthereum7702Authorization evaluates EIP-7702 delegation contracts
	FieldSourceEthereum7702Authorization FieldSource = "ethereum_7702_authorization"
	// FieldSourceEthereumMessage evaluates personal message signing
	FieldSourceEthereumMessage FieldSource = "ethereum_message"
	// FieldSourceSystem evaluates against system-level data
	FieldSourceSystem FieldSource = "system"
)

// ConditionOperator represents comparison operators for conditions
type ConditionOperator string

const (
	// OperatorEq equals comparison
	OperatorEq ConditionOperator = "eq"
	// OperatorNeq not equals comparison
	OperatorNeq ConditionOperator = "neq"
	// OperatorLt less than comparison
	OperatorLt ConditionOperator = "lt"
	// OperatorLte less than or equal comparison
	OperatorLte ConditionOperator = "lte"
	// OperatorGt greater than comparison
	OperatorGt ConditionOperator = "gt"
	// OperatorGte greater than or equal comparison
	OperatorGte ConditionOperator = "gte"
	// OperatorIn membership check (value in array)
	OperatorIn ConditionOperator = "in"
	// OperatorInConditionSet references an external condition set
	OperatorInConditionSet ConditionOperator = "in_condition_set"
)

// RuleAction represents what action to take when rule matches
type RuleAction string

const (
	// ActionAllow allows the operation
	ActionAllow RuleAction = "ALLOW"
	// ActionDeny denies the operation
	ActionDeny RuleAction = "DENY"
)

// PolicyCondition represents a single condition in a policy rule
// Matches Privy's field_source/operator schema
type PolicyCondition struct {
	// FieldSource specifies where to get the field value from
	FieldSource FieldSource `json:"field_source"`
	// Field is the field name to evaluate (supports dot notation for nested fields)
	Field string `json:"field"`
	// Operator is the comparison operator
	Operator ConditionOperator `json:"operator"`
	// Value is the comparison value (string, number, or array for "in" operator)
	Value interface{} `json:"value"`
}

// PolicyRule represents a rule within a policy
type PolicyRule struct {
	// Name is a human-readable description of the rule
	Name string `json:"name"`
	// Method specifies which RPC method this rule applies to
	// Can be specific like "eth_sendTransaction" or wildcard "*"
	Method string `json:"method"`
	// Conditions is a list of conditions that must all be satisfied
	Conditions []PolicyCondition `json:"conditions"`
	// Action specifies what to do when rule matches (ALLOW or DENY)
	Action RuleAction `json:"action"`
}

// PolicySchema represents the top-level policy structure matching Privy's format
type PolicySchema struct {
	// Version is the policy schema version (always "1.0")
	Version string `json:"version"`
	// Name is a human-readable name for this policy
	Name string `json:"name"`
	// ChainType specifies which blockchain this policy applies to
	ChainType string `json:"chain_type"`
	// Rules is an ordered list of rules to evaluate
	// First matching rule determines the outcome
	Rules []PolicyRule `json:"rules"`
}

// EthereumTransactionFields are the available fields for ethereum_transaction field_source
var EthereumTransactionFields = map[string]string{
	"to":    "Target address of the transaction",
	"value": "Native token amount in wei",
	"from":  "Sender address",
	"data":  "Raw transaction data",
}

// EthereumCalldataFields are example fields for ethereum_calldata field_source
// The actual fields depend on the ABI being decoded
var EthereumCalldataFields = map[string]string{
	"transfer.to":     "ERC20 transfer recipient",
	"transfer.amount": "ERC20 transfer amount",
	"approve.spender": "ERC20 approval spender",
	"approve.amount":  "ERC20 approval amount",
}

// EthereumTypedDataDomainFields are fields for ethereum_typed_data_domain
var EthereumTypedDataDomainFields = map[string]string{
	"chainId":           "Chain ID in the EIP-712 domain",
	"verifyingContract": "Contract address in the EIP-712 domain",
	"name":              "Name in the EIP-712 domain",
	"version":           "Version in the EIP-712 domain",
}

// SystemFields are fields for system field_source
var SystemFields = map[string]string{
	"current_unix_timestamp": "Current time as Unix timestamp (seconds)",
}
