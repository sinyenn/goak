package aes

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
	"goak/crypto/padding"
)

var key128 = "1234567890123456"
var key192 = "123456789012345678901234"
var key256 = "12345678901234567890123456789012"
var iv = "1234567890123456"
var noPaddingPlainText = "hello!!world!!!!"
var plainText = "hello!"

type TestCaseData struct {
	key       string
	keySize   int
	iv        string
	mode      Mode
	padMode   padding.PaddingMode
	planiText string
}

func TestAES(t *testing.T) {
	var tcds = []TestCaseData{
		{key128, 128, "", ECB, padding.NoPadding{}, noPaddingPlainText},
		{key128, 128, "", ECB, padding.ZeroPadding{}, plainText},
		{key128, 128, "", ECB, padding.X923Padding{}, plainText},
		{key128, 128, "", ECB, padding.ISO10126Padding{}, plainText},
		{key128, 128, "", ECB, padding.PKCS7Padding{}, plainText},
		{key192, 192, "", ECB, padding.NoPadding{}, noPaddingPlainText},
		{key192, 192, "", ECB, padding.ZeroPadding{}, plainText},
		{key192, 192, "", ECB, padding.X923Padding{}, plainText},
		{key192, 192, "", ECB, padding.ISO10126Padding{}, plainText},
		{key192, 192, "", ECB, padding.PKCS7Padding{}, plainText},
		{key256, 256, "", ECB, padding.NoPadding{}, noPaddingPlainText},
		{key256, 256, "", ECB, padding.ZeroPadding{}, plainText},
		{key256, 256, "", ECB, padding.X923Padding{}, plainText},
		{key256, 256, "", ECB, padding.ISO10126Padding{}, plainText},
		{key256, 256, "", ECB, padding.PKCS7Padding{}, plainText},

		{key128, 128, iv, CBC, padding.NoPadding{}, noPaddingPlainText},
		{key128, 128, iv, CBC, padding.ZeroPadding{}, plainText},
		{key128, 128, iv, CBC, padding.X923Padding{}, plainText},
		{key128, 128, iv, CBC, padding.ISO10126Padding{}, plainText},
		{key128, 128, iv, CBC, padding.PKCS7Padding{}, plainText},
		{key192, 192, iv, CBC, padding.NoPadding{}, noPaddingPlainText},
		{key192, 192, iv, CBC, padding.ZeroPadding{}, plainText},
		{key192, 192, iv, CBC, padding.X923Padding{}, plainText},
		{key192, 192, iv, CBC, padding.ISO10126Padding{}, plainText},
		{key192, 192, iv, CBC, padding.PKCS7Padding{}, plainText},
		{key256, 256, iv, CBC, padding.NoPadding{}, noPaddingPlainText},
		{key256, 256, iv, CBC, padding.ZeroPadding{}, plainText},
		{key256, 256, iv, CBC, padding.X923Padding{}, plainText},
		{key256, 256, iv, CBC, padding.ISO10126Padding{}, plainText},
		{key256, 256, iv, CBC, padding.PKCS7Padding{}, plainText},

		{key128, 128, iv, CTR, padding.NoPadding{}, noPaddingPlainText},
		{key128, 128, iv, CTR, padding.ZeroPadding{}, plainText},
		{key128, 128, iv, CTR, padding.X923Padding{}, plainText},
		{key128, 128, iv, CTR, padding.ISO10126Padding{}, plainText},
		{key128, 128, iv, CTR, padding.PKCS7Padding{}, plainText},
		{key192, 192, iv, CTR, padding.NoPadding{}, noPaddingPlainText},
		{key192, 192, iv, CTR, padding.ZeroPadding{}, plainText},
		{key192, 192, iv, CTR, padding.X923Padding{}, plainText},
		{key192, 192, iv, CTR, padding.ISO10126Padding{}, plainText},
		{key192, 192, iv, CTR, padding.PKCS7Padding{}, plainText},
		{key256, 256, iv, CTR, padding.NoPadding{}, noPaddingPlainText},
		{key256, 256, iv, CTR, padding.ZeroPadding{}, plainText},
		{key256, 256, iv, CTR, padding.X923Padding{}, plainText},
		{key256, 256, iv, CTR, padding.ISO10126Padding{}, plainText},
		{key256, 256, iv, CTR, padding.PKCS7Padding{}, plainText},

		{key128, 128, iv, CFB, padding.NoPadding{}, noPaddingPlainText},
		{key128, 128, iv, CFB, padding.ZeroPadding{}, plainText},
		{key128, 128, iv, CFB, padding.X923Padding{}, plainText},
		{key128, 128, iv, CFB, padding.ISO10126Padding{}, plainText},
		{key128, 128, iv, CFB, padding.PKCS7Padding{}, plainText},
		{key192, 192, iv, CFB, padding.NoPadding{}, noPaddingPlainText},
		{key192, 192, iv, CFB, padding.ZeroPadding{}, plainText},
		{key192, 192, iv, CFB, padding.X923Padding{}, plainText},
		{key192, 192, iv, CFB, padding.ISO10126Padding{}, plainText},
		{key192, 192, iv, CFB, padding.PKCS7Padding{}, plainText},
		{key256, 256, iv, CFB, padding.NoPadding{}, noPaddingPlainText},
		{key256, 256, iv, CFB, padding.ZeroPadding{}, plainText},
		{key256, 256, iv, CFB, padding.X923Padding{}, plainText},
		{key256, 256, iv, CFB, padding.ISO10126Padding{}, plainText},
		{key256, 256, iv, CFB, padding.PKCS7Padding{}, plainText},

		{key128, 128, iv, OFB, padding.NoPadding{}, noPaddingPlainText},
		{key128, 128, iv, OFB, padding.ZeroPadding{}, plainText},
		{key128, 128, iv, OFB, padding.X923Padding{}, plainText},
		{key128, 128, iv, OFB, padding.ISO10126Padding{}, plainText},
		{key128, 128, iv, OFB, padding.PKCS7Padding{}, plainText},
		{key192, 192, iv, OFB, padding.NoPadding{}, noPaddingPlainText},
		{key192, 192, iv, OFB, padding.ZeroPadding{}, plainText},
		{key192, 192, iv, OFB, padding.X923Padding{}, plainText},
		{key192, 192, iv, OFB, padding.ISO10126Padding{}, plainText},
		{key192, 192, iv, OFB, padding.PKCS7Padding{}, plainText},
		{key256, 256, iv, OFB, padding.NoPadding{}, noPaddingPlainText},
		{key256, 256, iv, OFB, padding.ZeroPadding{}, plainText},
		{key256, 256, iv, OFB, padding.X923Padding{}, plainText},
		{key256, 256, iv, OFB, padding.ISO10126Padding{}, plainText},
		{key256, 256, iv, OFB, padding.PKCS7Padding{}, plainText},
	}
	for _, tcd := range tcds {
		err := testAES(tcd)
		if err != nil {
			t.Fatal(err)
		}
	}

}

func testAES(tcd TestCaseData) (err error) {
	aes, err := New(tcd.key, tcd.keySize, tcd.iv, tcd.mode, tcd.padMode)
	fmt.Println(aes.Name())
	encrypter, err := aes.Encrypter([]byte(tcd.planiText))
	fmt.Println("txt: " + tcd.planiText)
	hexStr := hex.EncodeToString(encrypter)
	base64Str := base64.StdEncoding.EncodeToString(encrypter)
	fmt.Println("txt->hex: " + hexStr)
	fmt.Println("txt->base64: " + base64Str)

	hexData := []byte(hexStr)
	n, err := hex.Decode(hexData, hexData)
	if err != nil {
		panic(err)
	}
	hexData = hexData[:n]
	decrypter, err := aes.Decrypter(hexData)
	fmt.Println("hex->txt: " + string(decrypter))
	base64Data := []byte(base64Str)
	n, err = base64.StdEncoding.Decode(base64Data, base64Data)
	if err != nil {
		panic(err)
	}
	base64Data = base64Data[:n]
	decrypter, err = aes.Decrypter(base64Data)
	fmt.Println("base64->txt: " + string(decrypter))

	fmt.Println("================================")
	return
}
