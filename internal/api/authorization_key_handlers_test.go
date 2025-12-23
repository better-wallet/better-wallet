package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeHexPublicKey_P256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecdhPub, err := priv.PublicKey.ECDH()
	require.NoError(t, err)
	uncompressed := ecdhPub.Bytes()
	compressed := elliptic.MarshalCompressed(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)

	t.Run("uncompressed_ok", func(t *testing.T) {
		got, err := decodeHexPublicKey("0x" + hex.EncodeToString(uncompressed))
		require.NoError(t, err)
		require.Equal(t, uncompressed, got)
	})

	t.Run("compressed_ok", func(t *testing.T) {
		got, err := decodeHexPublicKey("0x" + hex.EncodeToString(compressed))
		require.NoError(t, err)
		require.Equal(t, uncompressed, got)
	})

	t.Run("invalid_hex_rejected", func(t *testing.T) {
		_, err := decodeHexPublicKey("0xzz")
		require.Error(t, err)
	})

	t.Run("odd_length_hex_rejected", func(t *testing.T) {
		_, err := decodeHexPublicKey("0x123")
		require.Error(t, err)
	})

	t.Run("invalid_point_rejected", func(t *testing.T) {
		// 0x04 || 64 bytes of zeros is not a valid P-256 point.
		invalid := make([]byte, 65)
		invalid[0] = 0x04
		_, err := decodeHexPublicKey("0x" + hex.EncodeToString(invalid))
		require.Error(t, err)
	})

	t.Run("invalid_length_rejected", func(t *testing.T) {
		_, err := decodeHexPublicKey("0x" + hex.EncodeToString([]byte{0x04, 0x01}))
		require.Error(t, err)
	})
}

func TestEncodeHexPublicKey(t *testing.T) {
	b := []byte{0x04, 0x01, 0x02}
	require.Equal(t, "0x"+hex.EncodeToString(b), encodeHexPublicKey(b))
}

func FuzzDecodeHexPublicKey(f *testing.F) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(f, err)

	ecdhPub, err := priv.PublicKey.ECDH()
	require.NoError(f, err)
	uncompressed := "0x" + hex.EncodeToString(ecdhPub.Bytes())
	compressed := "0x" + hex.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y))

	f.Add(uncompressed)
	f.Add(compressed)
	f.Add("0x")
	f.Add("0x123")
	f.Add("not-hex")

	f.Fuzz(func(t *testing.T, hexKey string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("decodeHexPublicKey panicked: %v", r)
			}
		}()

		_, _ = decodeHexPublicKey(hexKey)
	})
}
