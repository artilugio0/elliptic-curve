package becc

import (
	"bytes"
	"strings"
	"testing"
)

func TestSecp256k1HybridEncryption(t *testing.T) {
	ecc := Secp256k1ECC()

	plaintext := "this is a test plaintext"

	priv, pub, err := ecc.GenKeyPair()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ciphertext, err := pub.Encrypt(strings.NewReader(plaintext))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	decrypted, err := priv.Decrypt(bytes.NewReader(ciphertext))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(decrypted) != plaintext {
		t.Errorf("got '%s', expected '%s'", string(decrypted), plaintext)
	}
}
