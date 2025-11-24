package policy

import (
	"context"
	"fmt"
	"math/big"
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

	// Transaction information
	To     *string
	Value  *big.Int
	Data   []byte
	Method *string

	// Session signer information (if applicable)
	SessionSigner *types.SessionSigner

	// Request metadata
	Timestamp time.Time
	Actor     string
}

// EvaluationResult contains the result of policy evaluation
type EvaluationResult struct {
	Decision PolicyDecision
	Reason   string
	Policy   *types.Policy
}

// Engine is the policy evaluation engine
type Engine struct {
	// Future: add caching, metrics, etc.
}

// NewEngine creates a new policy engine
func NewEngine() *Engine {
	return &Engine{}
}

// Evaluate evaluates a request against policies
func (e *Engine) Evaluate(ctx context.Context, policies []*types.Policy, evalCtx *EvaluationContext) (*EvaluationResult, error) {
	// If no policies are configured, allow by default (permissive mode for MVP)
	// In production, you may want to require at least one policy
	if len(policies) == 0 {
		return &EvaluationResult{
			Decision: DecisionAllow,
			Reason:   "No policies configured - allowing by default",
		}, nil
	}

	// Default deny - if no policies explicitly allow, deny
	result := &EvaluationResult{
		Decision: DecisionDeny,
		Reason:   "No policy explicitly allows this action",
	}

	// Evaluate each policy
	for _, policy := range policies {
		// Check if policy applies to this chain type
		if policy.ChainType != evalCtx.ChainType && policy.ChainType != "*" {
			continue
		}

		// Evaluate the policy rules
		decision, reason := e.evaluatePolicy(policy, evalCtx)

		// If any policy explicitly denies, return immediately (DENY > ALLOW)
		if decision == DecisionDeny {
			result.Decision = DecisionDeny
			result.Reason = reason
			result.Policy = policy
			return result, nil
		}

		// If this policy allows, mark it but continue checking for denies
		if decision == DecisionAllow {
			result.Decision = DecisionAllow
			result.Reason = "Policy allows this action"
			result.Policy = policy
		}
	}

	return result, nil
}

// evaluatePolicy evaluates a single policy
func (e *Engine) evaluatePolicy(policy *types.Policy, evalCtx *EvaluationContext) (PolicyDecision, string) {
	rules, ok := policy.Rules["rules"].([]interface{})
	if !ok {
		return DecisionDeny, "Invalid policy rules format"
	}

	// If no rules, deny by default
	if len(rules) == 0 {
		return DecisionDeny, "No rules defined in policy"
	}

	// Evaluate each rule
	for _, ruleInterface := range rules {
		rule, ok := ruleInterface.(map[string]interface{})
		if !ok {
			continue
		}

		// Check if this rule applies
		if !e.ruleApplies(rule, evalCtx) {
			continue
		}

		// Evaluate conditions
		decision, reason := e.evaluateConditions(rule, evalCtx)
		if decision == DecisionDeny {
			return DecisionDeny, reason
		}

		// If we found an applicable rule that allows, return allow
		if decision == DecisionAllow {
			return DecisionAllow, "Rule allows this action"
		}
	}

	return DecisionDeny, "No applicable rule found"
}

// ruleApplies checks if a rule applies to the current context
func (e *Engine) ruleApplies(rule map[string]interface{}, evalCtx *EvaluationContext) bool {
	// Check if rule has an action filter
	if action, ok := rule["action"].(string); ok {
		// For now, we support "sign_transaction" and "sign_message"
		// This can be extended based on the actual action in evalCtx
		_ = action
	}

	// Check if rule has a method filter (for smart contract interactions)
	if methods, ok := rule["methods"].([]interface{}); ok && evalCtx.Method != nil {
		found := false
		for _, m := range methods {
			if methodStr, ok := m.(string); ok && methodStr == *evalCtx.Method {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// evaluateConditions evaluates the conditions in a rule
func (e *Engine) evaluateConditions(rule map[string]interface{}, evalCtx *EvaluationContext) (PolicyDecision, string) {
	conditions, ok := rule["conditions"].([]interface{})
	if !ok || len(conditions) == 0 {
		// No conditions means allow
		return DecisionAllow, ""
	}

	for _, condInterface := range conditions {
		cond, ok := condInterface.(map[string]interface{})
		if !ok {
			continue
		}

		// Evaluate each condition type
		condType, ok := cond["type"].(string)
		if !ok {
			continue
		}

		switch condType {
		case "max_value":
			if !e.checkMaxValue(cond, evalCtx) {
				return DecisionDeny, "Transaction value exceeds maximum allowed"
			}

		case "address_whitelist":
			if !e.checkAddressWhitelist(cond, evalCtx) {
				return DecisionDeny, "Recipient address not in whitelist"
			}

		case "address_blacklist":
			if e.checkAddressBlacklist(cond, evalCtx) {
				return DecisionDeny, "Recipient address is blacklisted"
			}

		case "rate_limit":
			// This would require state tracking - simplified for MVP
			// In production, this would check against a rate limiter
			if !e.checkRateLimit(cond, evalCtx) {
				return DecisionDeny, "Rate limit exceeded"
			}

		case "time_window":
			if !e.checkTimeWindow(cond, evalCtx) {
				return DecisionDeny, "Action not allowed in current time window"
			}
		}
	}

	return DecisionAllow, ""
}

// checkMaxValue checks if the transaction value is within the allowed maximum
func (e *Engine) checkMaxValue(cond map[string]interface{}, evalCtx *EvaluationContext) bool {
	maxValueStr, ok := cond["value"].(string)
	if !ok {
		return true
	}

	maxValue, ok := new(big.Int).SetString(maxValueStr, 10)
	if !ok {
		return true
	}

	if evalCtx.Value == nil {
		return true
	}

	return evalCtx.Value.Cmp(maxValue) <= 0
}

// checkAddressWhitelist checks if the recipient is in the whitelist
func (e *Engine) checkAddressWhitelist(cond map[string]interface{}, evalCtx *EvaluationContext) bool {
	addresses, ok := cond["addresses"].([]interface{})
	if !ok || evalCtx.To == nil {
		return true
	}

	for _, addr := range addresses {
		if addrStr, ok := addr.(string); ok && addrStr == *evalCtx.To {
			return true
		}
	}

	return false
}

// checkAddressBlacklist checks if the recipient is in the blacklist
func (e *Engine) checkAddressBlacklist(cond map[string]interface{}, evalCtx *EvaluationContext) bool {
	addresses, ok := cond["addresses"].([]interface{})
	if !ok || evalCtx.To == nil {
		return false
	}

	for _, addr := range addresses {
		if addrStr, ok := addr.(string); ok && addrStr == *evalCtx.To {
			return true
		}
	}

	return false
}

// checkRateLimit checks rate limiting (simplified - would need state in production)
func (e *Engine) checkRateLimit(cond map[string]interface{}, evalCtx *EvaluationContext) bool {
	// TODO: Implement proper rate limiting with state tracking
	// For MVP, we'll always allow
	return true
}

// checkTimeWindow checks if the current time is within the allowed window
func (e *Engine) checkTimeWindow(cond map[string]interface{}, evalCtx *EvaluationContext) bool {
	start, hasStart := cond["start"].(string)
	end, hasEnd := cond["end"].(string)

	if !hasStart || !hasEnd {
		return true
	}

	// Parse times (simplified - assumes HH:MM format)
	currentTime := evalCtx.Timestamp.Format("15:04")

	// Simple string comparison (works for HH:MM format)
	return currentTime >= start && currentTime <= end
}

// ValidatePolicy validates that a policy is well-formed
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

	// Validate rules structure
	rules, ok := policy.Rules["rules"].([]interface{})
	if !ok {
		return fmt.Errorf("rules must be an array")
	}

	for i, ruleInterface := range rules {
		rule, ok := ruleInterface.(map[string]interface{})
		if !ok {
			return fmt.Errorf("rule %d is not a valid object", i)
		}

		// Validate rule has required fields
		if _, ok := rule["action"]; !ok {
			return fmt.Errorf("rule %d missing 'action' field", i)
		}
	}

	return nil
}
