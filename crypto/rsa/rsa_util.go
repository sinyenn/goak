package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

func Encrypt(plaintext string, publickey *rsa.PublicKey) (string, error) {
	label := []byte("")
	sha256hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(sha256hash, rand.Reader, publickey, []byte(plaintext), label)
	decodedtext := base64.StdEncoding.EncodeToString(ciphertext)
	return decodedtext, err
}

func Decrypt(ciphertext string, privatekey *rsa.PrivateKey) (string, error) {
	decodedtext, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed, error=%s\n", err.Error())
	}
	sha256hash := sha256.New()
	decryptedtext, err := rsa.DecryptOAEP(sha256hash, rand.Reader, privatekey, decodedtext, nil)
	if err != nil {
		return "", fmt.Errorf("RSA decrypt failed, error=%s\n", err.Error())
	}
	return string(decryptedtext), nil
}
