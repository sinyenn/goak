package padding

type PaddingMode interface {
	Padding(cipherText []byte, blockSize int) ([]byte, error)
	UnPadding(cipherText []byte, blockSize int) ([]byte, error)
	Name() string
}

func getPaddingSize(cipherText []byte, blockSize int) int {
	remainder := len(cipherText) % blockSize
	/**
	再提醒一下就是如果刚满blockSize个，那就要在补充称blockSize个字节。一定要比原先的多。（每种补充都要满足这样。这里非常容易被忽略）.
	这样再代入加密算法才是最正确的AES
	*/
	if remainder == 0 {
		return blockSize
	} else {
		return blockSize - remainder
	}
}
