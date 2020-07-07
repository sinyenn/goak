package padding

import "bytes"

type ZeroPadding struct {
}

func (p ZeroPadding) Name() string {
	return "ZeroPadding"
}

//ZeroPadding 填充0x00
func (p ZeroPadding) Padding(cipherText []byte, blockSize int) ([]byte, error) {
	ps := getPaddingSize(cipherText, blockSize)
	padData := bytes.Repeat([]byte{0}, ps)
	return append(cipherText, padData...),nil
}

//UnZeroPadding 去掉0x00
func (p ZeroPadding) UnPadding(cipherText []byte, blockSize int) ([]byte, error){
	return bytes.TrimFunc(cipherText, func(r rune) bool {
		return r == rune(0)
	}),nil
}
