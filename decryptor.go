//go:build windows
// +build windows

// Package main 提供 AutoClaw 桌面端凭据解密的独立 Go 命令行参考实现。
// 运行方法:
//   go run decryptor.go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	modcrypt32             = syscall.NewLazyDLL("crypt32.dll")
	procCryptUnprotectData = modcrypt32.NewProc("CryptUnprotectData")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func dpapiUnprotect(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("待解密数据为空")
	}
	var inBlob dataBlob
	inBlob.cbData = uint32(len(data))
	inBlob.pbData = &data[0]

	var outBlob dataBlob
	r, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData 失败: %v", err)
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(unsafe.Pointer(outBlob.pbData))))

	res := make([]byte, int(outBlob.cbData))
	copy(res, unsafe.Slice(outBlob.pbData, int(outBlob.cbData)))
	return res, nil
}

type localState struct {
	OSCrypt struct {
		EncryptedKey string `json:"encrypted_key"`
	} `json:"os_crypt"`
}

type authFile struct {
	DeviceID     string `json:"deviceId"`
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
	UserInfo     struct {
		ID        string `json:"id"`
		UserID    string `json:"user_id"`
		UserPhone string `json:"user_phone"`
	} `json:"userInfo"`
}

func getSafeAppdataDir() (string, error) {
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		return "", errors.New("APPDATA 环境变量未定义")
	}
	base := filepath.Clean(appdata)
	target := filepath.Join(base, "autoclaw")

	rel, err := filepath.Rel(base, target)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", errors.New("安全校验失败：检测到目录穿越")
	}
	return target, nil
}

func readSafeFile(dir, filename string) ([]byte, error) {
	cleanName := filepath.Base(filename)
	fullPath := filepath.Join(dir, cleanName)

	rel, err := filepath.Rel(dir, fullPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return nil, errors.New("安全校验失败：禁止非法文件路径访问")
	}
	return os.ReadFile(fullPath)
}

func getMasterKey(dir string) ([]byte, error) {
	raw, err := readSafeFile(dir, "Local State")
	if err != nil {
		return nil, fmt.Errorf("读取 Local State 失败: %w", err)
	}

	var state localState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("解析 Local State 格式失败: %w", err)
	}

	if state.OSCrypt.EncryptedKey == "" {
		return nil, errors.New("Local State 中缺少 encrypted_key")
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(state.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("base64 解码 encrypted_key 失败: %w", err)
	}

	if len(encryptedKey) < 5 || string(encryptedKey[:5]) != "DPAPI" {
		return nil, errors.New("encrypted_key 未包含 DPAPI 头部魔数")
	}

	return dpapiUnprotect(encryptedKey[5:])
}

func decryptToken(encVal string, masterKey []byte) (string, error) {
	if !strings.HasPrefix(encVal, "enc:") {
		return encVal, nil
	}
	b64Data := strings.TrimPrefix(encVal, "enc:")
	raw, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return "", fmt.Errorf("base64 解码失败: %w", err)
	}

	// 报文结构: v10(3字节) + IV(12字节) + Ciphertext + Tag(16字节)
	if len(raw) < 3+12+16 {
		return "", errors.New("密文数据长度不满足规范")
	}
	if string(raw[:3]) != "v10" {
		return "", errors.New("不支持的 safeStorage 版本标识")
	}

	iv := raw[3 : 3+12]
	payload := raw[3+12:]

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := aesgcm.Open(nil, iv, payload, nil)
	if err != nil {
		return "", fmt.Errorf("AES-GCM 解密失败 (Tag 不匹配): %w", err)
	}

	res := string(plaintext)
	if !strings.HasPrefix(res, "Bearer ") {
		res = "Bearer " + res
	}
	return res, nil
}

func main() {
	fmt.Println(strings.Repeat("=", 65))
	fmt.Println("AutoClaw 桌面端凭据本地自动化解密提取程序 (Go 实现)")
	fmt.Println(strings.Repeat("=", 65))

	dir, err := getSafeAppdataDir()
	if err != nil {
		fmt.Printf("[错误] 定位目录失败: %v\n", err)
		return
	}

	masterKey, err := getMasterKey(dir)
	if err != nil {
		fmt.Printf("[错误] 获取 DPAPI 主密钥失败: %v\n", err)
		return
	}

	authRaw, err := readSafeFile(dir, "auth.json")
	if err != nil {
		authRaw, err = readSafeFile(dir, "token-cache.json")
		if err != nil {
			fmt.Printf("[错误] 读取 auth.json 凭证文件失败: %v\n", err)
			return
		}
	}

	var auth authFile
	if err := json.Unmarshal(authRaw, &auth); err != nil {
		fmt.Printf("[错误] 反序列化 JSON 失败: %v\n", err)
		return
	}

	accessToken, err := decryptToken(auth.Token, masterKey)
	if err != nil {
		fmt.Printf("[错误] 解密 Access Token 失败: %v\n", err)
		return
	}

	refreshToken, _ := decryptToken(auth.RefreshToken, masterKey)

	fmt.Printf("用户 ID       : %s\n", auth.UserInfo.UserID)
	fmt.Printf("用户编号     : %s\n", auth.UserInfo.ID)
	fmt.Printf("绑定手机     : %s\n", auth.UserInfo.UserPhone)
	fmt.Printf("设备 ID       : %s\n", auth.DeviceID)

	// 安全打印片段与总长度
	if len(accessToken) > 20 {
		fmt.Printf("Access Token  : %s... (有效长度: %d)\n", accessToken[:20], len(accessToken))
	}
	if len(refreshToken) > 20 {
		fmt.Printf("Refresh Token : %s... (有效长度: %d)\n", refreshToken[:20], len(refreshToken))
	}
	fmt.Println(strings.Repeat("=", 65))
	fmt.Println("[提示] 解密出的 Access Token 已包含 'Bearer ' 前缀，可直接用于请求 Authorization 头。")
}
