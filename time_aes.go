package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strconv"

	"github.com/beevik/ntp"
)

// key不能泄露
var randomSeed string

var PwdKey = []byte(generateRandomString(randomSeed, 22))

func main() {
	if len(os.Args) < 4 {
		fmt.Println("参数缺失！\n 请输入TimeAes ec/dc 文件路径 时间戳")
		return
	}
	CURRENT_TIME, err := ntp.Time("ntp1.aliyun.com")
	if err != nil {
		fmt.Println(err)
		return
	}
	filePath := os.Args[2]
	crypt := os.Args[1]
	if !(crypt == "ec" || crypt == "dc") {
		fmt.Println("操作类型错误！")
		return
	}
	ts := os.Args[3]
	TS, err := strconv.Atoi(ts)
	if err != nil {
		panic("时间戳格式错误!")
	}
	PwdKey = []byte(string(PwdKey) + ts)
	if crypt == "ec" {
		fi, err := os.Open(filePath)
		if err != nil {
			panic("文件路径错误!")
		}
		fileBytes, err := io.ReadAll(fi)
		if err != nil {
			panic("文件读取失败!")
		}
		ecfi, err := os.Create("ec_result")
		if err != nil {
			panic("文件创建失败!")
		}
		fi.Close()
		ecbyte, err := EncryptByAes(fileBytes)
		if err != nil {
			panic("文件加密失败!")
		}
		ecfi.Write(ecbyte)
		ecfi.Close()

	} else {
		if int(CURRENT_TIME.Unix()) < TS {
			panic("解密时间未到!")
		}
		fi, err := os.Open(filePath)
		if err != nil {
			panic("文件路径错误!")
		}
		fileBytes, err := io.ReadAll(fi)
		if err != nil {
			panic("读取文件失败!")
		}
		ecfi, err := os.Create("dc_result")
		if err != nil {
			panic("文件创建失败")
		}
		fi.Close()
		ecbyte, err := DecryptByAes(fileBytes)
		if err != nil {
			panic("解密失败")
		}
		ecfi.Write(ecbyte)
		ecfi.Close()
	}

}

// pkcs7Padding 填充
func pkcs7Padding(data []byte, blockSize int) []byte {
	//判断缺少几位长度。最少1，最多 blockSize
	padding := blockSize - len(data)%blockSize
	//补足位数。把切片[]byte{byte(padding)}复制padding个
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// pkcs7UnPadding 填充的反向操作
func pkcs7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("加密字符串错误！")
	}
	//获取填充的个数
	unPadding := int(data[length-1])
	return data[:(length - unPadding)], nil
}

// AesEncrypt 加密
func AesEncrypt(data []byte, key []byte) ([]byte, error) {
	//创建加密实例
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//判断加密快的大小
	blockSize := block.BlockSize()
	//填充
	encryptBytes := pkcs7Padding(data, blockSize)
	//初始化加密数据接收切片
	crypted := make([]byte, len(encryptBytes))
	//使用cbc加密模式
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	//执行加密
	blockMode.CryptBlocks(crypted, encryptBytes)
	return crypted, nil
}

// AesDecrypt 解密
func AesDecrypt(data []byte, key []byte) ([]byte, error) {
	//创建实例
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//获取块的大小
	blockSize := block.BlockSize()
	//使用cbc
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	//初始化解密数据接收切片
	crypted := make([]byte, len(data))
	//执行解密
	blockMode.CryptBlocks(crypted, data)
	//去除填充
	crypted, err = pkcs7UnPadding(crypted)
	if err != nil {
		return nil, err
	}
	return crypted, nil
}

// EncryptByAes Aes加密 后 base64 再加
func EncryptByAes(data []byte) ([]byte, error) {
	res, err := AesEncrypt(data, PwdKey)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// DecryptByAes Aes 解密
func DecryptByAes(data []byte) ([]byte, error) {
	sEnc := base64.StdEncoding.EncodeToString(data)
	dataByte, err := base64.StdEncoding.DecodeString(sEnc)
	if err != nil {
		return nil, err
	}
	return AesDecrypt(dataByte, PwdKey)
}

const RANDOM_DICT = `qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890!@#$%^&*()`

func generateRandomString(seedStr string, length int) string {
	seed, _ := strconv.ParseInt(seedStr, 10, 10)
	rs := rand.NewSource(seed) // 设置随机种子
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		// 从字典中随机选择一个字符
		result[i] = RANDOM_DICT[rand.New(rs).Intn(len(RANDOM_DICT))]
	}
	return string(result)
}
