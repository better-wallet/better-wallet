package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem/schemes"
)

// GenerateP256KeyPair generates a new P-256 ECDSA key pair
// Returns (privateKeyBytes, publicKeyBytes, error)
func GenerateP256KeyPair() ([]byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate P-256 key: %w", err)
	}

	// Marshal private key to DER format
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Marshal public key to DER format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	return privateKeyBytes, publicKeyBytes, nil
}

// EncryptWithHPKE encrypts plaintext using HPKE with the recipient's public key
// Returns (encapsulatedKey, ciphertext, error)
// Uses DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
func EncryptWithHPKE(plaintext []byte, recipientPublicKey []byte) ([]byte, []byte, error) {
	// Parse recipient's public key
	pub, err := x509.ParsePKIXPublicKey(recipientPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse recipient public key: %w", err)
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("recipient public key is not ECDSA")
	}

	// Create HPKE suite
	suite := hpke.NewSuite(hpke.KEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)

	// Get the KEM scheme for P-256
	kemScheme := schemes.ByName("HPKE_KEM_P256_HKDF_SHA256")

	// Marshal public key for KEM
	pkBytes := elliptic.Marshal(ecdsaPub.Curve, ecdsaPub.X, ecdsaPub.Y)
	recipientPk, err := kemScheme.UnmarshalBinaryPublicKey(pkBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal public key for KEM: %w", err)
	}

	// Setup sender and encrypt
	sender, err := suite.NewSender(recipientPk, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create sender: %w", err)
	}

	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to setup sender: %w", err)
	}

	ciphertext, err := sealer.Seal(plaintext, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to seal: %w", err)
	}

	return enc, ciphertext, nil
}

// DecryptWithHPKE decrypts ciphertext using HPKE with the recipient's private key
// Returns decrypted plaintext or error
func DecryptWithHPKE(ciphertext []byte, encapsulatedKey []byte, recipientPrivateKey []byte) ([]byte, error) {
	// Parse recipient's private key
	privKey, err := x509.ParseECPrivateKey(recipientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse recipient private key: %w", err)
	}

	// Create HPKE suite
	suite := hpke.NewSuite(hpke.KEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)

	// Get the KEM scheme for P-256
	kemScheme := schemes.ByName("HPKE_KEM_P256_HKDF_SHA256")

	// Marshal private key for KEM (need D value padded to 32 bytes)
	skBytes := privKey.D.Bytes()
	if len(skBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(skBytes):], skBytes)
		skBytes = padded
	}

	recipientSk, err := kemScheme.UnmarshalBinaryPrivateKey(skBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key for KEM: %w", err)
	}

	// Setup receiver and decrypt
	receiver, err := suite.NewReceiver(recipientSk, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create receiver: %w", err)
	}

	opener, err := receiver.Setup(encapsulatedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to setup receiver: %w", err)
	}

	plaintext, err := opener.Open(ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open: %w", err)
	}

	return plaintext, nil
}
