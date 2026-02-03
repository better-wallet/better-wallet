package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationErrors is a collection of validation errors
type ValidationErrors []ValidationError

func (ve ValidationErrors) Error() string {
	if len(ve) == 0 {
		return "validation failed"
	}
	msgs := make([]string, len(ve))
	for i, e := range ve {
		msgs[i] = fmt.Sprintf("%s: %s", e.Field, e.Message)
	}
	return strings.Join(msgs, "; ")
}

// Validator provides validation methods
type Validator struct {
	errors ValidationErrors
}

// NewValidator creates a new validator
func NewValidator() *Validator {
	return &Validator{errors: make(ValidationErrors, 0)}
}

// HasErrors returns true if there are validation errors
func (v *Validator) HasErrors() bool {
	return len(v.errors) > 0
}

// Errors returns all validation errors
func (v *Validator) Errors() ValidationErrors {
	return v.errors
}

// AddError adds a validation error
func (v *Validator) AddError(field, message string) {
	v.errors = append(v.errors, ValidationError{Field: field, Message: message})
}

// Required validates that a string is not empty
func (v *Validator) Required(field, value string) bool {
	if strings.TrimSpace(value) == "" {
		v.AddError(field, "is required")
		return false
	}
	return true
}

// MinLength validates minimum string length
func (v *Validator) MinLength(field, value string, minLen int) bool {
	if len(value) < minLen {
		v.AddError(field, fmt.Sprintf("must be at least %d characters", minLen))
		return false
	}
	return true
}

// MaxLength validates maximum string length
func (v *Validator) MaxLength(field, value string, maxLen int) bool {
	if len(value) > maxLen {
		v.AddError(field, fmt.Sprintf("must be at most %d characters", maxLen))
		return false
	}
	return true
}

// UUID validates that a string is a valid UUID
func (v *Validator) UUID(field, value string) bool {
	if _, err := uuid.Parse(value); err != nil {
		v.AddError(field, "must be a valid UUID")
		return false
	}
	return true
}

// Email validates that a string is a valid email
func (v *Validator) Email(field, value string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(value) {
		v.AddError(field, "must be a valid email address")
		return false
	}
	return true
}

// EthereumAddress validates that a string is a valid Ethereum address
func (v *Validator) EthereumAddress(field, value string) bool {
	if value == "" {
		return true // Optional field
	}
	addressRegex := regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`)
	if !addressRegex.MatchString(value) {
		v.AddError(field, "must be a valid Ethereum address")
		return false
	}
	return true
}

// HexString validates that a string is valid hex
func (v *Validator) HexString(field, value string) bool {
	if value == "" {
		return true // Optional field
	}
	hexRegex := regexp.MustCompile(`^(0x)?[a-fA-F0-9]+$`)
	if !hexRegex.MatchString(value) {
		v.AddError(field, "must be a valid hex string")
		return false
	}
	return true
}

// OneOf validates that a value is one of the allowed values
func (v *Validator) OneOf(field, value string, allowed []string) bool {
	for _, a := range allowed {
		if value == a {
			return true
		}
	}
	v.AddError(field, fmt.Sprintf("must be one of: %s", strings.Join(allowed, ", ")))
	return false
}

// PositiveInt validates that an integer is positive
func (v *Validator) PositiveInt(field string, value int) bool {
	if value <= 0 {
		v.AddError(field, "must be a positive integer")
		return false
	}
	return true
}

// NonNegativeInt validates that an integer is non-negative
func (v *Validator) NonNegativeInt(field string, value int) bool {
	if value < 0 {
		v.AddError(field, "must be a non-negative integer")
		return false
	}
	return true
}

// WriteValidationError writes validation errors as JSON response
func WriteValidationError(w http.ResponseWriter, errors ValidationErrors) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error":  "validation failed",
		"code":   "VALIDATION_ERROR",
		"errors": errors,
	})
}

// ValidateJSON decodes and validates JSON request body
func ValidateJSON(r *http.Request, v interface{}) error {
	if r.Body == nil {
		return fmt.Errorf("request body is required")
	}

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	return nil
}
