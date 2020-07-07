package padding

import "crypto/rand"

type ISO10126Padding struct {
}
func (p ISO10126Padding) Name() string {
	return "ISO10126Padding"
}

//ISO10126Padding 填充至符合块大小的整数倍，填充值最后一个字节为填充的数量数，其他字节随机处理
func (p ISO10126Padding) Padding(cipherText []byte, blockSize int) ([]byte, error) {
	ps := getPaddingSize(cipherText, blockSize)
	padData := make([]byte, ps-1)
	_, err := rand.Read(padData)
	if err != nil {
		return nil, err
	}
	padData = append(padData, byte(ps))
	return append(cipherText, padData...), nil
}

//UnISO10126Padding
func (p ISO10126Padding) UnPadding(cipherText []byte, blockSize int) ([]byte, error) {
	ps := int(cipherText[len(cipherText)-1])
	return cipherText[:len(cipherText)-ps], nil
}
