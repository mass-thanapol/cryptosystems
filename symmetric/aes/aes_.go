package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
)

// The same encryption key is used for both encryption and decryption.
// The same encryption key will generate different ciphertexts.
// Use cases: encrypted file, encrypted data.

func Encrypt(plaintext string, encryptionKey string) (string, error) {
	if encryptionKey == "" {
		return "", nil
	}
	key := []byte(encryptionKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	cipherTextBytes := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	cipherText := hex.EncodeToString(append(nonce, cipherTextBytes...))
	return cipherText, nil
}

func Decrypt(ciphertext string, encryptionKey string) (string, error) {
	ciphertextBytes, _ := hex.DecodeString(ciphertext)
	if encryptionKey == "" {
		return ciphertext, nil
	}
	key := []byte(encryptionKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, _ := cipher.NewGCM(block)
	if len(ciphertext) < gcm.NonceSize() {
		return "", errors.New("invalid nonce size")
	}
	plaintextBytes, err := gcm.Open(nil,
		ciphertextBytes[:gcm.NonceSize()],
		ciphertextBytes[gcm.NonceSize():],
		nil,
	)
	return string(plaintextBytes), err
}
