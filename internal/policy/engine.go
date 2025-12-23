package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/better-wallet/better-wallet/pkg/types"
)

// PolicyDecision represents the result of policy evaluation
type PolicyDecision int

const (
	// DecisionDeny denies the request
	DecisionDeny PolicyDecision = iota
	// DecisionAllow allows the request
	DecisionAllow
)

// EvaluationContext contains the context for policy evaluation
type EvaluationContext struct {
	// Wallet information
	WalletID  string
	ChainType string
	Address   string

	// Transaction information (for ethereum_transaction field_source)
	To      *string
	Value   *big.Int
	Data    []byte
	ChainID int64

	// Method being called (eth_sendTransaction, eth_signTypedData_v4, etc.)
	Method string

	// Typed data information (for ethereum_typed_data_* field_sources)
	TypedDataDomain  map[string]interface{}
	TypedDataMessage map[string]interface{}

	// Personal message (for ethereum_message field_source)
	PersonalMessage string

	// EIP-7702 authorization (for ethereum_7702_authorization field_source)
	AuthorizationContract string

	// Decoded calldata (for ethereum_calldata field_source)
	DecodedCalldata map[string]interface{}

	// Session signer information (if applicable)
	SessionSigner *types.SessionSigner

	// Request metadata
	Timestamp time.Time
	Actor     string

	// ConditionSets maps condition set IDs to their values for in_condition_set operator
	ConditionSets map[string][]interface{}
}

// EvaluationResult contains the result of policy evaluation
type EvaluationResult struct {
	Decision PolicyDecision
	Reason   string
	Policy   *types.Policy
	Rule     *types.PolicyRule
}

// compiledPolicyEntry holds a compiled policy schema and its content hash
type compiledPolicyEntry struct {
	schema      *types.PolicySchema
	contentHash string
}

// Engine is the policy evaluation engine
type Engine struct {
	// schemaCache maps policy ID to compiled schema with content hash for invalidation
	schemaCache sync.Map // map[string]*compiledPolicyEntry
}

// NewEngine creates a new policy engine
func NewEngine() *Engine {
	return &Engine{}
}

// getCompiledSchema retrieves or compiles the policy schema with caching
// Cache key is policy ID, and content hash is used to detect changes
func (e *Engine) getCompiledSchema(policy *types.Policy) (*types.PolicySchema, error) {
	policyID := policy.ID.String()

	// Compute content hash for cache invalidation
	rulesBytes, _ := json.Marshal(policy.Rules)
	hash := sha256.Sum256(rulesBytes)
	contentHash := hex.EncodeToString(hash[:8]) // Use first 8 bytes for efficiency

	// Check cache
	if cached, ok := e.schemaCache.Load(policyID); ok {
		entry := cached.(*compiledPolicyEntry)
		if entry.contentHash == contentHash {
			return entry.schema, nil
		}
		// Content changed, need to recompile
	}

	// Compile and cache
	schema, err := e.parsePolicySchema(policy)
	if err != nil {
		return nil, err
	}

	e.schemaCache.Store(policyID, &compiledPolicyEntry{
		schema:      schema,
		contentHash: contentHash,
	})

	return schema, nil
}

// Evaluate evaluates a request against policies
// Uses default-deny semantics: if no policies are configured, the request is denied
func (e *Engine) Evaluate(ctx context.Context, policies []*types.Policy, evalCtx *EvaluationContext) (*EvaluationResult, error) {
	// Default-deny: if no policies are configured, deny the request
	if len(policies) == 0 {
		return &EvaluationResult{
			Decision: DecisionDeny,
			Reason:   "No policies configured - default deny",
		}, nil
	}

	// Evaluate each policy
	for _, policy := range policies {
		// Check if policy applies to this chain type
		if policy.ChainType != evalCtx.ChainType && policy.ChainType != "*" {
			continue
		}

		// Get compiled policy schema (uses cache for performance)
		schema, err := e.getCompiledSchema(policy)
		if err != nil {
			// Invalid schema - deny with error
			return &EvaluationResult{
				Decision: DecisionDeny,
				Reason:   fmt.Sprintf("Invalid policy schema: %v", err),
				Policy:   policy,
			}, nil
		}

		// Evaluate using field_source/operator schema
		result := e.evaluatePolicySchema(schema, evalCtx, policy)
		if result != nil {
			return result, nil
		}
	}

	// Default: deny if no explicit allow
	return &EvaluationResult{
		Decision: DecisionDeny,
		Reason:   "No policy rule explicitly allows this action",
	}, nil
}

// parsePolicySchema parses policy rules into schema format
func (e *Engine) parsePolicySchema(policy *types.Policy) (*types.PolicySchema, error) {
	if rules, ok := policy.Rules["rules"].([]interface{}); ok {
		schema := &types.PolicySchema{
			Version:   types.PolicyVersion,
			Name:      policy.Name,
			ChainType: policy.ChainType,
		}

		for _, ruleInterface := range rules {
			ruleMap, ok := ruleInterface.(map[string]interface{})
			if !ok {
				continue
			}

			// Check if rule has conditions
			conditionsRaw, hasConditionsField := ruleMap["conditions"]
			conditions, conditionsIsArray := conditionsRaw.([]interface{})

			// If conditions field exists but is wrong type, reject as invalid
			if hasConditionsField && !conditionsIsArray {
				return nil, fmt.Errorf("invalid rule format: conditions must be an array")
			}

			// If conditions exist and have values, verify ALL conditions are valid maps with field_source
			if conditionsIsArray && len(conditions) > 0 {
				for i, cond := range conditions {
					condMap, ok := cond.(map[string]interface{})
					if !ok {
						return nil, fmt.Errorf("invalid rule format: condition %d must be a map", i)
					}
					if _, hasFieldSource := condMap["field_source"]; !hasFieldSource {
						return nil, fmt.Errorf("invalid rule format: condition %d missing field_source", i)
					}
				}
			}

			// Parse rule (rules without conditions or with empty conditions are valid - they match all requests)
			rule, err := e.parseRule(ruleMap)
			if err != nil {
				continue
			}
			schema.Rules = append(schema.Rules, *rule)
		}

		if len(schema.Rules) > 0 {
			return schema, nil
		}
	}

	return nil, fmt.Errorf("no valid rules found")
}

// parseRule parses a rule in field_source/operator format
func (e *Engine) parseRule(ruleMap map[string]interface{}) (*types.PolicyRule, error) {
	rule := &types.PolicyRule{}

	if name, ok := ruleMap["name"].(string); ok {
		rule.Name = name
	}

	if method, ok := ruleMap["method"].(string); ok {
		rule.Method = method
	} else {
		rule.Method = "*"
	}

	if action, ok := ruleMap["action"].(string); ok {
		rule.Action = types.RuleAction(action)
	} else {
		rule.Action = types.ActionDeny
	}

	// Parse conditions
	if conditions, ok := ruleMap["conditions"].([]interface{}); ok {
		for _, condInterface := range conditions {
			condMap, ok := condInterface.(map[string]interface{})
			if !ok {
				continue
			}

			cond := types.PolicyCondition{}

			if fieldSource, ok := condMap["field_source"].(string); ok {
				cond.FieldSource = types.FieldSource(fieldSource)
			}
			if field, ok := condMap["field"].(string); ok {
				cond.Field = field
			}
			if operator, ok := condMap["operator"].(string); ok {
				cond.Operator = types.ConditionOperator(operator)
			}
			cond.Value = condMap["value"]

			rule.Conditions = append(rule.Conditions, cond)
		}
	}

	return rule, nil
}

// evaluatePolicySchema evaluates using the field_source/operator schema
func (e *Engine) evaluatePolicySchema(schema *types.PolicySchema, evalCtx *EvaluationContext, policy *types.Policy) *EvaluationResult {
	// Rules are evaluated in order - first matching rule determines outcome
	for i := range schema.Rules {
		rule := &schema.Rules[i]

		// Check if method matches
		if rule.Method != "*" && rule.Method != evalCtx.Method {
			continue
		}

		// Evaluate all conditions (AND logic)
		allMatch := true
		for _, cond := range rule.Conditions {
			if !e.evaluateCondition(cond, evalCtx) {
				allMatch = false
				break
			}
		}

		if allMatch {
			decision := DecisionDeny
			if rule.Action == types.ActionAllow {
				decision = DecisionAllow
			}

			return &EvaluationResult{
				Decision: decision,
				Reason:   fmt.Sprintf("Rule '%s' matched with action %s", rule.Name, rule.Action),
				Policy:   policy,
				Rule:     rule,
			}
		}
	}

	return nil
}

// evaluateCondition evaluates a single condition
func (e *Engine) evaluateCondition(cond types.PolicyCondition, evalCtx *EvaluationContext) bool {
	// Get the actual value from context based on field_source
	actualValue := e.getFieldValue(cond.FieldSource, cond.Field, evalCtx)
	if actualValue == nil {
		// Field not found - condition cannot match
		return false
	}

	// Compare using the operator
	return e.compareValues(actualValue, cond.Operator, cond.Value, evalCtx)
}

// getFieldValue extracts a field value from the evaluation context
func (e *Engine) getFieldValue(fieldSource types.FieldSource, field string, evalCtx *EvaluationContext) interface{} {
	switch fieldSource {
	case types.FieldSourceEthereumTransaction:
		return e.getEthereumTransactionField(field, evalCtx)
	case types.FieldSourceEthereumCalldata:
		return e.getEthereumCalldataField(field, evalCtx)
	case types.FieldSourceEthereumTypedDataDomain:
		return e.getNestedField(evalCtx.TypedDataDomain, field)
	case types.FieldSourceEthereumTypedDataMessage:
		return e.getNestedField(evalCtx.TypedDataMessage, field)
	case types.FieldSourceEthereum7702Authorization:
		if field == "contract" {
			return evalCtx.AuthorizationContract
		}
	case types.FieldSourceEthereumMessage:
		if field == "message" {
			return evalCtx.PersonalMessage
		}
	case types.FieldSourceSystem:
		return e.getSystemField(field, evalCtx)
	}
	return nil
}

// getEthereumTransactionField gets a field from transaction data
func (e *Engine) getEthereumTransactionField(field string, evalCtx *EvaluationContext) interface{} {
	switch field {
	case "to":
		if evalCtx.To != nil {
			return strings.ToLower(*evalCtx.To)
		}
	case "value":
		if evalCtx.Value != nil {
			return evalCtx.Value.String()
		}
	case "from":
		return strings.ToLower(evalCtx.Address)
	case "data":
		if evalCtx.Data != nil {
			return hex.EncodeToString(evalCtx.Data)
		}
	case "chain_id":
		return evalCtx.ChainID
	}
	return nil
}

// getEthereumCalldataField gets a field from decoded calldata
func (e *Engine) getEthereumCalldataField(field string, evalCtx *EvaluationContext) interface{} {
	if evalCtx.DecodedCalldata == nil {
		return nil
	}
	return e.getNestedField(evalCtx.DecodedCalldata, field)
}

// getSystemField gets a system-level field
func (e *Engine) getSystemField(field string, evalCtx *EvaluationContext) interface{} {
	switch field {
	case "current_unix_timestamp":
		return evalCtx.Timestamp.Unix()
	}
	return nil
}

// getNestedField extracts a nested field value using dot notation
func (e *Engine) getNestedField(data map[string]interface{}, field string) interface{} {
	if data == nil {
		return nil
	}

	parts := strings.Split(field, ".")
	current := interface{}(data)

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		default:
			return nil
		}
	}

	return current
}

// compareValues compares two values using the specified operator
func (e *Engine) compareValues(actual interface{}, operator types.ConditionOperator, expected interface{}, evalCtx *EvaluationContext) bool {
	switch operator {
	case types.OperatorEq:
		return e.valuesEqual(actual, expected)
	case types.OperatorNeq:
		return !e.valuesEqual(actual, expected)
	case types.OperatorLt:
		cmp, ok := e.compareBigInt(actual, expected)
		return ok && cmp < 0
	case types.OperatorLte:
		cmp, ok := e.compareBigInt(actual, expected)
		return ok && cmp <= 0
	case types.OperatorGt:
		cmp, ok := e.compareBigInt(actual, expected)
		return ok && cmp > 0
	case types.OperatorGte:
		cmp, ok := e.compareBigInt(actual, expected)
		return ok && cmp >= 0
	case types.OperatorIn:
		return e.valueInArray(actual, expected)
	case types.OperatorInConditionSet:
		return e.valueInConditionSet(actual, expected, evalCtx)
	}
	return false
}

// valuesEqual checks if two values are equal
func (e *Engine) valuesEqual(actual, expected interface{}) bool {
	// Normalize addresses to lowercase for comparison
	actualStr := fmt.Sprintf("%v", actual)
	expectedStr := fmt.Sprintf("%v", expected)

	// Handle address comparison (case-insensitive)
	if strings.HasPrefix(actualStr, "0x") || strings.HasPrefix(expectedStr, "0x") {
		return strings.EqualFold(actualStr, expectedStr)
	}

	return actualStr == expectedStr
}

// compareBigInt compares two values as big integers.
// Returns (comparison result, true) if both values can be converted to big.Int.
// Returns (0, false) if conversion fails - callers should treat this as "condition not matched".
func (e *Engine) compareBigInt(actual, expected interface{}) (int, bool) {
	actualBig := e.toBigInt(actual)
	expectedBig := e.toBigInt(expected)

	if actualBig == nil || expectedBig == nil {
		// Conversion failed - return false to indicate comparison cannot be performed
		return 0, false
	}

	return actualBig.Cmp(expectedBig), true
}

// toBigInt converts a value to big.Int
func (e *Engine) toBigInt(v interface{}) *big.Int {
	switch val := v.(type) {
	case *big.Int:
		return val
	case string:
		n, ok := new(big.Int).SetString(val, 0)
		if ok {
			return n
		}
	case float64:
		return big.NewInt(int64(val))
	case int64:
		return big.NewInt(val)
	case int:
		return big.NewInt(int64(val))
	case json.Number:
		if n, err := val.Int64(); err == nil {
			return big.NewInt(n)
		}
	}
	return nil
}

// valueInArray checks if a value is in an array
func (e *Engine) valueInArray(actual, expected interface{}) bool {
	// Expected should be an array
	switch arr := expected.(type) {
	case []interface{}:
		actualStr := strings.ToLower(fmt.Sprintf("%v", actual))
		for _, item := range arr {
			itemStr := strings.ToLower(fmt.Sprintf("%v", item))
			if actualStr == itemStr {
				return true
			}
		}
	case []string:
		actualStr := strings.ToLower(fmt.Sprintf("%v", actual))
		for _, item := range arr {
			if actualStr == strings.ToLower(item) {
				return true
			}
		}
	}
	return false
}

// valueInConditionSet checks if a value is in a condition set
// The expected value should be a condition set ID (string or UUID)
func (e *Engine) valueInConditionSet(actual, expected interface{}, evalCtx *EvaluationContext) bool {
	if evalCtx == nil || evalCtx.ConditionSets == nil {
		return false
	}

	// Get condition set ID from expected value
	conditionSetID := fmt.Sprintf("%v", expected)

	// Look up the condition set values
	values, ok := evalCtx.ConditionSets[conditionSetID]
	if !ok {
		return false
	}

	// Check if actual value is in the condition set
	return e.valueInArray(actual, values)
}

// ValidatePolicy validates that a policy is well-formed using strict schema
func (e *Engine) ValidatePolicy(policy *types.Policy) error {
	if policy.Name == "" {
		return fmt.Errorf("policy name is required")
	}

	if policy.ChainType == "" {
		return fmt.Errorf("chain type is required")
	}

	if policy.Rules == nil {
		return fmt.Errorf("policy rules are required")
	}

	rules, ok := policy.Rules["rules"].([]interface{})
	if !ok {
		return fmt.Errorf("rules must be an array")
	}

	if len(rules) == 0 {
		return fmt.Errorf("at least one rule is required")
	}

	for i, ruleInterface := range rules {
		rule, ok := ruleInterface.(map[string]interface{})
		if !ok {
			return fmt.Errorf("rule %d is not a valid object", i)
		}

		// method is required
		if _, ok := rule["method"].(string); !ok {
			return fmt.Errorf("rule %d missing 'method' field", i)
		}

		// action is required
		action, ok := rule["action"].(string)
		if !ok {
			return fmt.Errorf("rule %d missing 'action' field", i)
		}
		if action != string(types.ActionAllow) && action != string(types.ActionDeny) {
			return fmt.Errorf("rule %d has invalid action '%s', must be ALLOW or DENY", i, action)
		}

		// conditions must use field_source/operator format
		conditions, ok := rule["conditions"].([]interface{})
		if !ok {
			return fmt.Errorf("rule %d missing 'conditions' array", i)
		}

		for j, condInterface := range conditions {
			if cond, ok := condInterface.(map[string]interface{}); ok {
				if err := e.validateCondition(cond, i, j); err != nil {
					return err
				}
			} else {
				return fmt.Errorf("rule %d condition %d is not a valid object", i, j)
			}
		}
	}

	return nil
}

// validateCondition validates a single condition using strict field_source/operator schema
func (e *Engine) validateCondition(cond map[string]interface{}, ruleIdx, condIdx int) error {
	// field_source is required
	fieldSource, ok := cond["field_source"].(string)
	if !ok {
		return fmt.Errorf("rule %d condition %d missing 'field_source'", ruleIdx, condIdx)
	}

	validSources := map[string]bool{
		string(types.FieldSourceEthereumTransaction):       true,
		string(types.FieldSourceEthereumCalldata):          true,
		string(types.FieldSourceEthereumTypedDataDomain):   true,
		string(types.FieldSourceEthereumTypedDataMessage):  true,
		string(types.FieldSourceEthereum7702Authorization): true,
		string(types.FieldSourceEthereumMessage):           true,
		string(types.FieldSourceSystem):                    true,
	}
	if !validSources[fieldSource] {
		return fmt.Errorf("rule %d condition %d has invalid field_source '%s'", ruleIdx, condIdx, fieldSource)
	}

	// field is required
	if _, ok := cond["field"].(string); !ok {
		return fmt.Errorf("rule %d condition %d missing 'field'", ruleIdx, condIdx)
	}

	// operator is required
	operator, ok := cond["operator"].(string)
	if !ok {
		return fmt.Errorf("rule %d condition %d missing 'operator'", ruleIdx, condIdx)
	}

	validOps := map[string]bool{
		string(types.OperatorEq):             true,
		string(types.OperatorNeq):            true,
		string(types.OperatorLt):             true,
		string(types.OperatorLte):            true,
		string(types.OperatorGt):             true,
		string(types.OperatorGte):            true,
		string(types.OperatorIn):             true,
		string(types.OperatorInConditionSet): true,
	}
	if !validOps[operator] {
		return fmt.Errorf("rule %d condition %d has invalid operator '%s'", ruleIdx, condIdx, operator)
	}

	// value is required
	if _, ok := cond["value"]; !ok {
		return fmt.Errorf("rule %d condition %d missing 'value'", ruleIdx, condIdx)
	}

	return nil
}
