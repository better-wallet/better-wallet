package keyexec

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	vault "github.com/hashicorp/vault/api"
)

// KMSProvider is an interface for key management services.
// Different KMS backends (local, AWS KMS, HashiCorp Vault, GCP KMS, Azure Key Vault)
// can implement this interface to provide encryption/decryption services.
type KMSProvider interface {
	// Encrypt encrypts data using the KMS
	Encrypt(ctx context.Context, data []byte) ([]byte, error)

	// Decrypt decrypts data using the KMS
	Decrypt(ctx context.Context, encryptedData []byte) ([]byte, error)

	// Provider returns the provider name (e.g., "local", "aws-kms", "vault")
	Provider() string
}

// KMSProviderType represents supported KMS providers
type KMSProviderType string

const (
	// KMSProviderLocal uses a local master key for encryption (development/simple deployments)
	KMSProviderLocal KMSProviderType = "local"

	// KMSProviderAWSKMS uses AWS KMS for encryption
	KMSProviderAWSKMS KMSProviderType = "aws-kms"

	// KMSProviderVault uses HashiCorp Vault Transit engine
	KMSProviderVault KMSProviderType = "vault"

	// KMSProviderGCPKMS uses GCP Cloud KMS (placeholder for future)
	// KMSProviderGCPKMS KMSProviderType = "gcp-kms"

	// KMSProviderAzureKeyVault uses Azure Key Vault (placeholder for future)
	// KMSProviderAzureKeyVault KMSProviderType = "azure-keyvault"
)

// KMSConfig contains configuration for KMS providers
type KMSConfig struct {
	// Provider specifies which KMS provider to use
	Provider string

	// Local provider config
	LocalMasterKeyHex string

	// AWS KMS config
	AWSKMSKeyID  string
	AWSKMSRegion string

	// Vault config
	VaultAddress   string
	VaultToken     string
	VaultTransitKey string
}

// LocalKMSProvider implements KMSProvider using a local master key with AES-GCM
// This is suitable for development or simple self-hosted deployments
type LocalKMSProvider struct {
	masterKey []byte
}

// NewLocalKMSProvider creates a new local KMS provider
func NewLocalKMSProvider(masterKeyHex string) (*LocalKMSProvider, error) {
	if masterKeyHex == "" {
		return nil, fmt.Errorf("master key is required for local KMS provider")
	}

	// Create 32-byte key from provided string
	// In production, this should be a proper hex-encoded 32-byte key
	masterKey := make([]byte, 32)
	copy(masterKey, []byte(masterKeyHex))

	return &LocalKMSProvider{
		masterKey: masterKey,
	}, nil
}

// Encrypt encrypts data using AES-GCM with the local master key
func (p *LocalKMSProvider) Encrypt(ctx context.Context, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using AES-GCM with the local master key
func (p *LocalKMSProvider) Decrypt(ctx context.Context, encryptedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// Provider returns the provider name
func (p *LocalKMSProvider) Provider() string {
	return string(KMSProviderLocal)
}

// AWSKMSProvider implements KMSProvider using AWS KMS
type AWSKMSProvider struct {
	keyID  string
	region string
	client *kms.Client
}

// NewAWSKMSProvider creates a new AWS KMS provider
func NewAWSKMSProvider(keyID, region string) (*AWSKMSProvider, error) {
	if keyID == "" {
		return nil, fmt.Errorf("AWS KMS key ID is required")
	}
	if region == "" {
		return nil, fmt.Errorf("AWS region is required")
	}

	// Load AWS configuration with specified region
	// Uses default credential chain: env vars, shared config, IAM role, etc.
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := kms.NewFromConfig(cfg)

	return &AWSKMSProvider{
		keyID:  keyID,
		region: region,
		client: client,
	}, nil
}

// Encrypt encrypts data using AWS KMS
func (p *AWSKMSProvider) Encrypt(ctx context.Context, data []byte) ([]byte, error) {
	output, err := p.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     aws.String(p.keyID),
		Plaintext: data,
	})
	if err != nil {
		return nil, fmt.Errorf("AWS KMS encrypt failed: %w", err)
	}
	return output.CiphertextBlob, nil
}

// Decrypt decrypts data using AWS KMS
func (p *AWSKMSProvider) Decrypt(ctx context.Context, encryptedData []byte) ([]byte, error) {
	output, err := p.client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:          aws.String(p.keyID),
		CiphertextBlob: encryptedData,
	})
	if err != nil {
		return nil, fmt.Errorf("AWS KMS decrypt failed: %w", err)
	}
	return output.Plaintext, nil
}

// Provider returns the provider name
func (p *AWSKMSProvider) Provider() string {
	return string(KMSProviderAWSKMS)
}

// VaultProvider implements KMSProvider using HashiCorp Vault Transit engine
type VaultProvider struct {
	transitKey string
	client     *vault.Client
}

// NewVaultProvider creates a new Vault provider
func NewVaultProvider(address, token, transitKey string) (*VaultProvider, error) {
	if address == "" {
		return nil, fmt.Errorf("Vault address is required")
	}
	if token == "" {
		return nil, fmt.Errorf("Vault token is required")
	}
	if transitKey == "" {
		return nil, fmt.Errorf("Vault transit key name is required")
	}

	// Initialize Vault client
	vaultConfig := vault.DefaultConfig()
	vaultConfig.Address = address

	client, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	client.SetToken(token)

	return &VaultProvider{
		transitKey: transitKey,
		client:     client,
	}, nil
}

// Encrypt encrypts data using Vault Transit engine
func (p *VaultProvider) Encrypt(ctx context.Context, data []byte) ([]byte, error) {
	// Vault Transit requires base64-encoded plaintext
	plaintext := base64.StdEncoding.EncodeToString(data)

	path := fmt.Sprintf("transit/encrypt/%s", p.transitKey)
	secret, err := p.client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"plaintext": plaintext,
	})
	if err != nil {
		return nil, fmt.Errorf("Vault Transit encrypt failed: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("Vault Transit encrypt returned empty response")
	}

	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return nil, fmt.Errorf("Vault Transit encrypt: ciphertext not found in response")
	}

	// Return ciphertext as bytes (it's a vault:v1:... string)
	return []byte(ciphertext), nil
}

// Decrypt decrypts data using Vault Transit engine
func (p *VaultProvider) Decrypt(ctx context.Context, encryptedData []byte) ([]byte, error) {
	path := fmt.Sprintf("transit/decrypt/%s", p.transitKey)
	secret, err := p.client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"ciphertext": string(encryptedData),
	})
	if err != nil {
		return nil, fmt.Errorf("Vault Transit decrypt failed: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("Vault Transit decrypt returned empty response")
	}

	plaintextB64, ok := secret.Data["plaintext"].(string)
	if !ok {
		return nil, fmt.Errorf("Vault Transit decrypt: plaintext not found in response")
	}

	// Decode base64 plaintext
	plaintext, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return nil, fmt.Errorf("Vault Transit decrypt: failed to decode plaintext: %w", err)
	}

	return plaintext, nil
}

// Provider returns the provider name
func (p *VaultProvider) Provider() string {
	return string(KMSProviderVault)
}

// NewKMSProvider creates a KMSProvider based on the configuration
func NewKMSProvider(cfg *KMSConfig) (KMSProvider, error) {
	provider := KMSProviderType(cfg.Provider)

	switch provider {
	case KMSProviderLocal, "": // Default to local
		return NewLocalKMSProvider(cfg.LocalMasterKeyHex)

	case KMSProviderAWSKMS:
		return NewAWSKMSProvider(cfg.AWSKMSKeyID, cfg.AWSKMSRegion)

	case KMSProviderVault:
		return NewVaultProvider(cfg.VaultAddress, cfg.VaultToken, cfg.VaultTransitKey)

	default:
		return nil, fmt.Errorf("unsupported KMS provider: %s (supported: %s, %s, %s)",
			provider, KMSProviderLocal, KMSProviderAWSKMS, KMSProviderVault)
	}
}

// Ensure providers implement KMSProvider
var (
	_ KMSProvider = (*LocalKMSProvider)(nil)
	_ KMSProvider = (*AWSKMSProvider)(nil)
	_ KMSProvider = (*VaultProvider)(nil)
)
