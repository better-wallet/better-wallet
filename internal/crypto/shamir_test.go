package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSplitKeySSS(t *testing.T) {
	// Generate a test private key (32 bytes)
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	t.Run("basic 2-of-2 split and combine", func(t *testing.T) {
		shareSet, err := SplitKeySSS(privateKey, 2, 2)
		if err != nil {
			t.Fatalf("SplitKeySSS failed: %v", err)
		}

		if shareSet.Threshold != 2 {
			t.Errorf("expected threshold 2, got %d", shareSet.Threshold)
		}
		if shareSet.TotalShares != 2 {
			t.Errorf("expected total shares 2, got %d", shareSet.TotalShares)
		}

		// Verify all shares are non-nil and have data
		if len(shareSet.AuthShare) == 0 {
			t.Error("auth share is empty")
		}
		if len(shareSet.ExecShare) == 0 {
			t.Error("exec share is empty")
		}
	})

	t.Run("combine auth and exec shares", func(t *testing.T) {
		shareSet, err := SplitKeySSS(privateKey, 2, 2)
		if err != nil {
			t.Fatalf("SplitKeySSS failed: %v", err)
		}

		reconstructed, err := CombineAuthAndExec(shareSet.AuthShare, shareSet.ExecShare)
		if err != nil {
			t.Fatalf("CombineAuthAndExec failed: %v", err)
		}

		if !bytes.Equal(reconstructed, privateKey) {
			t.Error("reconstructed key does not match original")
		}
	})
}

func TestSplitKeyDefault(t *testing.T) {
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	shareSet, err := SplitKeyDefault(privateKey)
	if err != nil {
		t.Fatalf("SplitKeyDefault failed: %v", err)
	}

	if shareSet.Threshold != DefaultThreshold {
		t.Errorf("expected threshold %d, got %d", DefaultThreshold, shareSet.Threshold)
	}
	if shareSet.TotalShares != DefaultTotalShares {
		t.Errorf("expected total shares %d, got %d", DefaultTotalShares, shareSet.TotalShares)
	}

	// Verify we can reconstruct
	reconstructed, err := CombineSharesSSS([][]byte{shareSet.AuthShare, shareSet.ExecShare})
	if err != nil {
		t.Fatalf("CombineSharesSSS failed: %v", err)
	}

	if !bytes.Equal(reconstructed, privateKey) {
		t.Error("reconstructed key does not match original")
	}
}

func TestSplitKeySSS_Errors(t *testing.T) {
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	t.Run("empty key", func(t *testing.T) {
		_, err := SplitKeySSS([]byte{}, 2, 2)
		if err == nil {
			t.Error("expected error for empty key")
		}
	})

	t.Run("threshold not 2", func(t *testing.T) {
		_, err := SplitKeySSS(privateKey, 1, 2)
		if err == nil {
			t.Error("expected error for threshold != 2")
		}
		_, err = SplitKeySSS(privateKey, 3, 3)
		if err == nil {
			t.Error("expected error for threshold != 2")
		}
	})

	t.Run("total shares not 2", func(t *testing.T) {
		_, err := SplitKeySSS(privateKey, 2, 3)
		if err == nil {
			t.Error("expected error for totalShares != 2")
		}
	})
}

func TestCombineSharesSSS_Errors(t *testing.T) {
	t.Run("insufficient shares", func(t *testing.T) {
		_, err := CombineSharesSSS([][]byte{[]byte("share1")})
		if err == nil {
			t.Error("expected error for insufficient shares")
		}
	})

	t.Run("too many shares", func(t *testing.T) {
		_, err := CombineSharesSSS([][]byte{[]byte("share1"), []byte("share2"), []byte("share3")})
		if err == nil {
			t.Error("expected error for too many shares")
		}
	})

	t.Run("empty share", func(t *testing.T) {
		_, err := CombineSharesSSS([][]byte{[]byte("share1"), nil})
		if err == nil {
			t.Error("expected error for empty share")
		}
	})
}

func TestValidateShare(t *testing.T) {
	t.Run("empty share", func(t *testing.T) {
		err := ValidateShare([]byte{})
		if err == nil {
			t.Error("expected error for empty share")
		}
	})

	t.Run("short share", func(t *testing.T) {
		err := ValidateShare(make([]byte, 10))
		if err == nil {
			t.Error("expected error for short share")
		}
	})

	t.Run("valid share length", func(t *testing.T) {
		err := ValidateShare(make([]byte, 33))
		if err != nil {
			t.Errorf("unexpected error for valid share: %v", err)
		}
	})
}
