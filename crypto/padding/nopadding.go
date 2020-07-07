package padding

type NoPadding struct {
}

func (p NoPadding) Name() string {
	return "NoPadding"
}

func (p NoPadding) Padding(cipherText []byte, blockSize int) ([]byte, error) {
	return cipherText, nil
}

func (p NoPadding) UnPadding(cipherText []byte, blockSize int) ([]byte, error) {
	return cipherText, nil
}
