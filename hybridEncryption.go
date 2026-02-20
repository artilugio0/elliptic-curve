package becc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"
)

func (pub PublicKey) Encrypt(input io.Reader) ([]byte, error) {
	ePriv, ePub, err := pub.ecc.GenKeyPair()
	if err != nil {
		return nil, err
	}

	plaintext, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}

	sharedSecret := ePriv.ECDH(pub)
	fmt.Printf("encrypt shared secret : %+v\n", sharedSecret)

	info := "becc hybrid file encryption v1"
	keyMaterial, err := hkdf.Expand(sha256.New, sharedSecret, info, 32+12)
	if err != nil {
		return nil, err
	}

	aesKey := keyMaterial[:32]
	aesNonce := keyMaterial[32:]
	fmt.Printf("encrypt aes nonce: %+v\n", aesNonce)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, aesNonce, plaintext, nil)

	result := slices.Concat(ePub.Compressed(), aesNonce, ciphertext)

	return result, nil
}

func (priv PrivateKey) Decrypt(input io.Reader) ([]byte, error) {
	inputBytes, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}

	compressedPub := inputBytes[:33]
	aesNonce := inputBytes[33:45]
	ciphertext := inputBytes[45:]

	fmt.Printf("decrypt aes nonce: %+v\n", aesNonce)

	pub, err := priv.ecc.NewPublicKeyCompressed(compressedPub)
	if err != nil {
		return nil, err
	}

	sharedSecret := priv.ECDH(pub)
	fmt.Printf("decrypt shared secret : %+v\n", sharedSecret)

	info := "becc hybrid file encryption v1"
	keyMaterial, err := hkdf.Expand(sha256.New, sharedSecret, info, 32+12)
	if err != nil {
		return nil, err
	}

	aesKey := keyMaterial[:32]
	aesNonce2 := keyMaterial[32:]
	if !bytes.Equal(aesNonce, aesNonce2) {
		return nil, errors.New("nonce missmatch")
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, aesNonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
