package ecc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

// Private key can generate public key.
// The public key is required for sign, and the private key is required for verify.
// The same encryption key will generate different ciphertexts.
// Use cases: Verifying blockchain transactions, Validate digital signature.
// Faster verification than RSA because it uses smaller keys compared to RSA at the same security level.
// ECC 256 bits = RSA 2,048 bits

// https://www.tencentcloud.com/document/product/1007/39989

func GenerateECDSAKey(bits elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	priv, err := ecdsa.GenerateKey(bits, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, &priv.PublicKey, nil
}

func ExportPrivateKeyToFile(priv *ecdsa.PrivateKey, filepath string) error {
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	privFile, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer privFile.Close()
	err = pem.Encode(privFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	if err != nil {
		return err
	}
	return nil
}

func ExportPublicKeyToFile(pub *ecdsa.PublicKey, filepath string) error {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	pubFile, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer pubFile.Close()
	err = pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	if err != nil {
		return err
	}
	return nil
}

func LoadPrivateKeyFromFile(filepath string) (*ecdsa.PrivateKey, error) {
	privBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(privBytes)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing the private key")
	}
	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

func LoadPublicKeyFromFile(filepath string) (*ecdsa.PublicKey, error) {
	pubBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pubBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing the public key")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pubKey.(*ecdsa.PublicKey), nil
}

func Sign(privFilePath string, message string) (string, error) {
	privKey, err := LoadPrivateKeyFromFile(privFilePath)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte(message))
	signature, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func VerifySignature(pubFilePath string, message, signature string) (bool, error) {
	pubKey, err := LoadPublicKeyFromFile(pubFilePath)
	if err != nil {
		return false, err
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}
	hash := sha256.Sum256([]byte(message))
	valid := ecdsa.VerifyASN1(pubKey, hash[:], signatureBytes)
	return valid, nil
}
