package padding

import "bytes"

type X923Padding struct {
}

func (p X923Padding) Name() string {
	return "ANSIX923Padding"
}

//X923Padding Zero的改进，最后一个字节为填充字节个数
func (p X923Padding) Padding(cipherText []byte, blockSize int) ([]byte, error) {
	ps := getPaddingSize(cipherText, blockSize)
	padData := bytes.Repeat([]byte{0}, ps-1)
	padData = append(padData, byte(ps))
	return append(cipherText, padData...),nil
}

//UnX923Padding
func (p X923Padding) UnPadding(cipherText []byte, blockSize int) ([]byte, error) {
	ps := int(cipherText[len(cipherText)-1])
	return cipherText[:len(cipherText)-ps],nil
}
