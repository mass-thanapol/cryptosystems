package ecc_test

import (
	"crypto/elliptic"
	"cryptosystems/asymmetric/ecc"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ECC(t *testing.T) {
	t.Run("Case_VerifySignature_Valid", func(t *testing.T) {
		privateKey, publicKey, _ := ecc.GenerateECDSAKey(elliptic.P256()) // prime field of 256 bits
		privFilePath := "./key/private_key.pem"
		ecc.ExportPrivateKeyToFile(privateKey, privFilePath)
		pubFilePath := "./key/public_key.pem"
		ecc.ExportPublicKeyToFile(publicKey, pubFilePath)
		message := "Hello, ECC Encryption and Decryption!"
		signature, _ := ecc.Sign(privFilePath, message)
		valid, _ := ecc.VerifySignature(pubFilePath, message, signature)
		expectation := true
		assert.Equal(t, expectation, valid)
	})
	t.Run("Case_VerifySignature_InValid", func(t *testing.T) {
		privateKey, publicKey, _ := ecc.GenerateECDSAKey(elliptic.P256()) // prime field of 256 bits
		privFilePath := "./key/private_key.pem"
		ecc.ExportPrivateKeyToFile(privateKey, privFilePath)
		pubFilePath := "./key/public_key.pem"
		ecc.ExportPublicKeyToFile(publicKey, pubFilePath)
		message := "Hello, ECC Encryption and Decryption!"
		signature, _ := ecc.Sign(privFilePath, message)
		valid, _ := ecc.VerifySignature(pubFilePath, message+"...", signature)
		expectation := false
		assert.Equal(t, expectation, valid)
	})
}
