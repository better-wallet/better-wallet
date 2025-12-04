package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAllSigningMethods(t *testing.T) {
	methods := AllSigningMethods()

	assert.Len(t, methods, 3)
	assert.Contains(t, methods, SignMethodTransaction)
	assert.Contains(t, methods, SignMethodPersonal)
	assert.Contains(t, methods, SignMethodTypedData)
}

func TestIsValidSigningMethod(t *testing.T) {
	tests := []struct {
		method string
		valid  bool
	}{
		{
			method: string(SignMethodTransaction),
			valid:  true,
		},
		{
			method: string(SignMethodPersonal),
			valid:  true,
		},
		{
			method: string(SignMethodTypedData),
			valid:  true,
		},
		{
			method: "sign_transaction",
			valid:  true,
		},
		{
			method: "personal_sign",
			valid:  true,
		},
		{
			method: "sign_typed_data",
			valid:  true,
		},
		{
			method: "invalid_method",
			valid:  false,
		},
		{
			method: "",
			valid:  false,
		},
		{
			method: "eth_signTransaction",
			valid:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			result := IsValidSigningMethod(tt.method)
			assert.Equal(t, tt.valid, result)
		})
	}
}

func TestSigningMethodConstants(t *testing.T) {
	assert.Equal(t, SigningMethod("sign_transaction"), SignMethodTransaction)
	assert.Equal(t, SigningMethod("personal_sign"), SignMethodPersonal)
	assert.Equal(t, SigningMethod("sign_typed_data"), SignMethodTypedData)
}

func TestChainTypeConstants(t *testing.T) {
	assert.Equal(t, "ethereum", ChainTypeEthereum)
	assert.Equal(t, "solana", ChainTypeSolana)
	assert.Equal(t, "bitcoin", ChainTypeBitcoin)
}

func TestExecBackendConstants(t *testing.T) {
	assert.Equal(t, "kms", ExecBackendKMS)
	assert.Equal(t, "tee", ExecBackendTEE)
}

func TestAuthKindConstants(t *testing.T) {
	assert.Equal(t, "oidc", AuthKindOIDC)
	assert.Equal(t, "jwt", AuthKindJWT)
}

func TestAlgorithmConstants(t *testing.T) {
	assert.Equal(t, "p256", AlgorithmP256)
}

func TestShareTypeConstants(t *testing.T) {
	assert.Equal(t, "auth_share", ShareTypeAuth)
	assert.Equal(t, "exec_share", ShareTypeExec)
	assert.Equal(t, "enclave_share", ShareTypeEnclave)
	assert.Equal(t, "recovery_share", ShareTypeRecovery)
}

func TestStatusConstants(t *testing.T) {
	assert.Equal(t, "active", StatusActive)
	assert.Equal(t, "rotated", StatusRotated)
	assert.Equal(t, "revoked", StatusRevoked)
	assert.Equal(t, "inactive", StatusInactive)
}

func TestAppStatusConstants(t *testing.T) {
	assert.Equal(t, "active", AppStatusActive)
	assert.Equal(t, "suspended", AppStatusSuspended)
	assert.Equal(t, "deleted", AppStatusDeleted)
}

func TestRecoveryMethodConstants(t *testing.T) {
	assert.Equal(t, "password", RecoveryMethodPassword)
	assert.Equal(t, "cloud_backup", RecoveryMethodCloudBackup)
	assert.Equal(t, "passkey", RecoveryMethodPasskey)
}
