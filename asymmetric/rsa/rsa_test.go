package rsa_test

import (
	"cryptosystems/asymmetric/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_RSA(t *testing.T) {
	t.Run("Case_Encrypt_And_Decrypt", func(t *testing.T) {
		bits := 2048
		privateKey, publicKey, _ := rsa.GenerateKeys(bits)
		privFilePath := "./key/private_key.pem"
		rsa.ExportPrivateKeyToFile(privateKey, privFilePath)
		pubFilePath := "./key/public_key.pem"
		rsa.ExportPublicKeyToFile(publicKey, pubFilePath)
		plainText := "abc"
		encText, _ := rsa.Encrypt(plainText, pubFilePath)
		decText, _ := rsa.Decrypt(encText, privFilePath)
		expectation := decText
		assert.Equal(t, expectation, plainText)
	})
	t.Run("Case_VerifySignature_Valid", func(t *testing.T) {
		bits := 2048
		privateKey, publicKey, _ := rsa.GenerateKeys(bits)
		privFilePath := "./key/private_key.pem"
		rsa.ExportPrivateKeyToFile(privateKey, privFilePath)
		pubFilePath := "./key/public_key.pem"
		rsa.ExportPublicKeyToFile(publicKey, pubFilePath)
		message := "Hello, ECC Encryption and Decryption!"
		signature, _ := rsa.Sign(privFilePath, message)
		valid, _ := rsa.VerifySignature(pubFilePath, message, signature)
		expectation := true
		assert.Equal(t, expectation, valid)
	})
	t.Run("Case_VerifySignature_InValid", func(t *testing.T) {
		bits := 2048
		privateKey, publicKey, _ := rsa.GenerateKeys(bits)
		privFilePath := "./key/private_key.pem"
		rsa.ExportPrivateKeyToFile(privateKey, privFilePath)
		pubFilePath := "./key/public_key.pem"
		rsa.ExportPublicKeyToFile(publicKey, pubFilePath)
		message := "Hello, ECC Encryption and Decryption!"
		signature, _ := rsa.Sign(privFilePath, message)
		valid, _ := rsa.VerifySignature(pubFilePath, message+"...", signature)
		expectation := false
		assert.Equal(t, expectation, valid)
	})
}
