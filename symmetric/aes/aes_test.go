package aes_test

import (
	"cryptosystems/symmetric/aes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_AES(t *testing.T) {
	t.Run("Case_Encrypt_And_Decrypt", func(t *testing.T) {
		plainText := "abc"
		encryptionKey := "Rtyuiokjhgfde45678iuyhgfdZZfghhk" // Length 32 is AES-256
		encText, _ := aes.Encrypt(plainText, encryptionKey)
		decText, _ := aes.Decrypt(encText, encryptionKey)
		expectation := decText
		assert.Equal(t, expectation, plainText)
	})
}
