package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/sinyenn/goak/crypto/padding"
	"strings"
)

type Mode int

const (
	ECB Mode = iota + 1
	CBC
	CTR
	CFB
	OFB
	GCM
)

type AES struct {
	key     string              //密钥
	keySize int                 //密钥长度，128、192、256
	iv      string              //初始向量
	mode    Mode                //加密模式
	padding padding.PaddingMode //填充方式

}

func (a *AES) Key() string {
	return a.key
}

func (a *AES) KeySize() int {
	return a.keySize
}

func (a *AES) IV() string {
	return a.iv
}

func (a *AES) Mode() string {
	switch a.mode {
	case ECB:
		return "ECB"
	case CBC:
		return "CBC"
	case CTR:
		return "CTR"
	case CFB:
		return "CFB"
	case OFB:
		return "OFB"
	case GCM:
		return "GCM"
	}
	return ""
}

func (a *AES) Padding() string {
	return a.padding.Name()
}

func (a *AES) Name() string {
	return fmt.Sprintf("AES-%d/%s/%s", a.KeySize(), a.Mode(), a.Padding())
}

func New(key string, keySize int, iv string, mode Mode, padMode padding.PaddingMode) (*AES, error) {
	if keySize != 128 && keySize != 192 && keySize != 256 {
		return nil, errors.New("密钥长度只能是128或192或256")
	}
	if strings.TrimSpace(key) == "" {
		key = generateKey(keySize)
	}
	if len([]byte(key))*8 != keySize {
		return nil, errors.New("密钥长度不匹配！")
	}
	//ECB无需IV
	if strings.TrimSpace(iv) == "" && mode != ECB {
		iv = generateKey(128)
	}
	if padMode == nil {
		padMode = padding.PKCS7Padding{}
	}
	a := &AES{
		key:     key,
		keySize: keySize,
		iv:      iv,
		mode:    mode,
		padding: padMode,
	}
	return a, nil
}

func generateKey(keySize int) string {
	//UUID去掉'-'后，最长为32个字符，256bit，符合aes最大密钥长度的要求，所以直接使用uuid按长度截取作为随机密钥
	uuid := strings.ReplaceAll(uuid.New().String(), "-", "")
	return uuid[:keySize/8]
}

func (a *AES) Encrypter(plainText []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(a.key))
	if err != nil {
		return nil, err
	}
	plainText, err = a.padding.Padding(plainText, block.BlockSize())
	if err != nil {
		return nil, err
	}
	dstBytes := make([]byte, len(plainText))
	var blockMode cipher.BlockMode
	var stream cipher.Stream
	switch a.mode {
	case ECB:
		blockMode = NewECBEncryptEr(block)
	case CBC:
		blockMode = cipher.NewCBCEncrypter(block, []byte(a.iv))
	case CTR:
		//CTR模式是异或运算，由于XOR操作的对称性，加密和解密操作是完全相同的
		stream = cipher.NewCTR(block, []byte(a.iv))
	case CFB:
		stream = cipher.NewCFBEncrypter(block, []byte(a.iv))
	case OFB:
		//OFB模式与CTR模式一样，都是是异或运算
		stream = cipher.NewOFB(block, []byte(a.iv))
	case GCM:
		//TODO https://www.golangprograms.com/data-encryption-with-aes-gcm.html
		return nil, errors.New("暂不支持GCM模式！")
	}
	switch a.mode {
	case ECB, CBC:
		blockMode.CryptBlocks(dstBytes, plainText)
	case CTR, OFB, CFB:
		stream.XORKeyStream(dstBytes, plainText)
	}

	return dstBytes, nil
}

func (a *AES) Decrypter(cipherText []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(a.key))
	if err != nil {
		return nil, err
	}
	dstBytes := make([]byte, len(cipherText))
	var blockMode cipher.BlockMode
	var stream cipher.Stream
	switch a.mode {
	case ECB:
		blockMode = NewECBDecryptEr(block)
	case CBC:
		blockMode = cipher.NewCBCDecrypter(block, []byte(a.iv))
	case CTR:
		//CTR模式是异或运算，由于XOR操作的对称性，加密和解密操作是完全相同的
		stream = cipher.NewCTR(block, []byte(a.iv))
	case CFB:
		stream = cipher.NewCFBDecrypter(block, []byte(a.iv))
	case OFB:
		//OFB模式与CTR模式一样，都是是异或运算
		stream = cipher.NewOFB(block, []byte(a.iv))
	case GCM:
		//TODO https://www.golangprograms.com/data-encryption-with-aes-gcm.html
		return nil, errors.New("暂不支持GCM模式！")
	}
	switch a.mode {
	case ECB, CBC:
		blockMode.CryptBlocks(dstBytes, cipherText)
	case CTR, OFB, CFB:
		stream.XORKeyStream(dstBytes, cipherText)
	}

	dstBytes, err = a.padding.UnPadding(dstBytes, block.BlockSize())
	if err != nil {
		return nil, err
	}
	return dstBytes, nil
}
