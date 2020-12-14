package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
)

/*
生成RSA密钥对, 包括private和public key

bits 密钥长度 1024,2048,4096
*/
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privatekey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	publickey := &privatekey.PublicKey
	return privatekey, publickey, nil
}

/*
PKCS1 padding dump private key
*/
func DumpPrivateKeyFile(privatekey *rsa.PrivateKey, filename string) error {
	bytes := x509.MarshalPKCS1PrivateKey(privatekey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: bytes,
	}
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

func LoadPrivateKeyFile(keyfile string) (*rsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("private key error!")
	}
	pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("parse private key error!")
	}
	return pk, nil
}

func DumpPublicKeyFile(publickey *rsa.PublicKey, filename string) error {
	bytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		return err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: bytes,
	}
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

func LoadPublicKeyFile(keyfile string) (*rsa.PublicKey, error) {
	bytes, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pki, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pk := pki.(*rsa.PublicKey)
	return pk, nil
}

func DumpPrivateKeyBase64(privatekey *rsa.PrivateKey) (string, error) {
	bytes := x509.MarshalPKCS1PrivateKey(privatekey)
	b64 := base64.StdEncoding.EncodeToString(bytes)
	return b64, nil
}

func LoadPrivateKeyBase64(base64key string) (*rsa.PrivateKey, error) {
	bytes, err := base64.StdEncoding.DecodeString(base64key)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed, error=%s\n", err.Error())
	}
	pk, err := x509.ParsePKCS1PrivateKey(bytes)
	if err != nil {
		return nil, errors.New("parse private key error!")
	}
	return pk, nil
}

func DumpPublicKeyBase64(publickey *rsa.PublicKey) (string, error) {
	bytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		return "", err
	}
	b64 := base64.StdEncoding.EncodeToString(bytes)
	return b64, nil
}

func LoadPublicKeyBase64(base64key string) (*rsa.PublicKey, error) {
	bytes, err := base64.StdEncoding.DecodeString(base64key)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed, error=%s\n", err.Error())
	}
	pki, err := x509.ParsePKIXPublicKey(bytes)
	if err != nil {
		return nil, err
	}
	pk := pki.(*rsa.PublicKey)
	return pk, nil
}
