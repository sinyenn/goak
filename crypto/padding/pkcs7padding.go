package padding

import (
	"bytes"
)

type PKCS7Padding struct {
}

func (p PKCS7Padding) Name() string {
	return "PKCS7Padding"
}

/**
PKCS7Padding是ANSI X.923的变体，PKCS7Padding的块大小可以在1~255的范围内
填充1个字符就全0x01
填充2个字符就全0x02
不需要填充就增加一个块，填充块长度，块长为8就填充0x08，块长为16就填充0x10
注：PKCS5Padding是PKCS7Padding的子集，块大小固定为8字节，可以直接由PKCS7Padding代替，只需将块大小设置为8即可
 */
func (p PKCS7Padding) Padding(cipherText []byte, blockSize int) ([]byte, error) {
	ps := getPaddingSize(cipherText, blockSize)
	padData := bytes.Repeat([]byte{byte(ps)}, ps)
	return append(cipherText, padData...), nil
}

//UnPKCS7Padding
func (p PKCS7Padding) UnPadding(cipherText []byte, blockSize int) ([]byte, error) {
	ps := int(cipherText[len(cipherText)-1])
	return cipherText[:len(cipherText)-ps], nil
}
