package file

import "os"

//判断指定路径的文件或文件夹是否存在
func IsExist(path string) bool {
	if _, err := os.Stat(path); err != nil {
		return false
	}
	return true
}

//判断指定路径是否为文件夹
func IsDir(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return s.IsDir()
}

//判断指定路径是否为文件
func IsFile(path string) bool {
	return !IsDir(path)
}
