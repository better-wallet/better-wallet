package storage

import "testing"

func TestAuthorizationKeyPublicKeyRoundTrip(t *testing.T) {
	original := []byte{0x04, 0x01, 0x02, 0xaa, 0xbb, 0xcc}
	encoded, err := encodeAuthorizationKeyPublicKey(original)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	decoded, err := decodeAuthorizationKeyPublicKey(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if string(decoded) != string(original) {
		t.Fatalf("round trip mismatch: got %x want %x", decoded, original)
	}
}

func TestAuthorizationKeyPublicKeyDecodeVariants(t *testing.T) {
	cases := []string{
		"0x040102aabbcc",
		"040102aabbcc",
		"  040102aabbcc  ",
	}

	for _, input := range cases {
		decoded, err := decodeAuthorizationKeyPublicKey(input)
		if err != nil {
			t.Fatalf("decode failed for %q: %v", input, err)
		}
		if len(decoded) == 0 {
			t.Fatalf("decode returned empty for %q", input)
		}
	}
}

func TestAuthorizationKeyPublicKeyDecodeErrors(t *testing.T) {
	if _, err := decodeAuthorizationKeyPublicKey(""); err == nil {
		t.Fatalf("expected error for empty input")
	}
	if _, err := decodeAuthorizationKeyPublicKey("0x123"); err == nil {
		t.Fatalf("expected error for odd length input")
	}
	if _, err := decodeAuthorizationKeyPublicKey("0xzz"); err == nil {
		t.Fatalf("expected error for invalid hex input")
	}
}

func TestAuthorizationKeyPublicKeyEncodeErrors(t *testing.T) {
	if _, err := encodeAuthorizationKeyPublicKey(nil); err == nil {
		t.Fatalf("expected error for empty public key")
	}
}
