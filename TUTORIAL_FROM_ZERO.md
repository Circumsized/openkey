# 从零开始搞懂 AutoClaw 桌面端凭据加解密：全流程逆向实战与手把手开发指南

> **面向读者**：无论是刚接触 Electron 逆向的新手、想将 AutoClaw 积分对接到本机 Agent 的开发者，还是想彻底弄明白 Chromium `safeStorage` 底层原理的技术人员，本文档将从**最基础的概念**开始，手把手带你一步一步还原整套算法。

---

## 目录

1. [前置概念科普：为什么我们需要解密？](#一前置概念科普为什么我们需要解密)
2. [第一步：探索与定位关键文件（文件在哪？长什么样？）](#二第一步探索与定位关键文件文件在哪长什么样)
3. [第二步：密码学机制全景拆解（两级加密是怎么工作的？）](#三第二步密码学机制全景拆解两级加密是怎么工作的)
4. [第三步：第一级解密——使用 DPAPI 提取 32 字节主密钥](#四第三步第一级解密使用-dpapi-提取-32-字节主密钥)
5. [第四步：第二级解密——使用 AES-256-GCM 还原明文 Token](#五第四步第二级解密使用-aes-256-gcm-还原明文-token)
6. [第五步：手把手带写代码（Go、Python、PowerShell 逐行精讲）](#六第五步手把手带写代码go-python-powershell-逐行精讲)
7. [第六步：血泪踩坑与调试实录（常见报错与排查清单）](#七第六步血泪踩坑与调试实录常见报错与排查清单)
8. [第七步：将解出的 Token 接入 OpenAI 兼容反向代理](#八第七步将解出的-token-接入-openai-兼容反向代理)

---

## 一、 前置概念科普：为什么我们需要解密？

### 1.1 为什么不想用传统的“抓包方式”？
如果你以前用过一些第三方 API 工具，通常需要打开 Fiddler / Charles / 浏览器 DevTools，按 F12 找到某个接口，复制 `Bearer eyJ...` 字符串。但这种方式存在三大痛点：
1. **麻烦且门槛高**：每次启动或换电脑都得抓包；
2. **时效性差**：AutoClaw 的 Access Token 有效期通常只有约 24 小时，过期后必须重新抓包；
3. **无法自动化**：外部 Agent（如 Claude Code, Open WebUI）需要全天候稳定可用，不可能每天人工去复制一次。

### 1.2 客户端自己是怎么维持登录的？
AutoClaw 桌面客户端（基于 Electron 开发）既然能记住登录态，说明它**必然在本地磁盘存了凭证**，并且定期在后台静默刷新这个凭据。
但为了防止恶意软件直接读取磁盘上的明文 JWT，Electron / Chromium 引入了系统的安全存储标准：**`safeStorage`**。

在 Windows 系统上，`safeStorage` 的底层机制就是：
> **Windows DPAPI (数据保护接口) + AES-256-GCM (对称加密算法)**

我们的目标，就是**利用与客户端相同的系统权限，在本地直接还原出明文 Token**，实现 1 秒内全自动无感读取！

---

## 二、 第一步：探索与定位关键文件（文件在哪？长什么样？）

打开 Windows 资源管理器，AutoClaw 在当前登录用户的电脑上留下了两个核心文件：

```
C:\Users\<你的用户名>\AppData\Roaming\autoclaw\
├── Local State     <-- 存储被操作系统锁定的主密钥 (Master Key)
└── auth.json       <-- 存储被加密后的各类令牌 (token, refreshToken)
```
*(注：在资源管理器地址栏直接输入 `%APPDATA%\autoclaw` 回车即可直达)*

---

### 2.1 剖析 `Local State` 文件
用文本编辑器打开 `Local State`，它是一个 JSON 文件，搜索 `os_crypt`：
```json
{
  "os_crypt": {
    "audit_enabled": false,
    "encrypted_key": "RFBBUEkBBAAAA...=="
  }
}
```
这里的 `os_crypt.encrypted_key` 是一段 Base64 编码的字符串。
它是被 Windows 操作系统锁定的密钥。

---

### 2.2 剖析 `auth.json` 文件
打开 `auth.json`，它的结构如下：
```json
{
  "deviceId": "d1ba71e9...",
  "token": "enc:djEw8okZRZ...",
  "refreshToken": "enc:djEw1xEshH...",
  "userInfo": {
    "id": "849168",
    "phone": "166****5952"
  }
}
```
注意观察：
- `token` 和 `refreshToken` 的值都是以 **`enc:`** 开头的长字符串！
- 去掉 `enc:` 之后，也是一段 Base64 密文。
- 只要我们能把它解密，里面就是货真价实的明文 `Bearer eyJ...`！

---

## 三、 第二步：密码学机制全景拆解（两级加密是怎么工作的？）

为什么不能直接拿密钥去解密？因为 Chromium 采用了**两级防护模型**：

```
+-------------------------------------------------------------------------------+
|                               两级加密链路全景图                              |
|                                                                               |
|  [阶段 1: 拿钥匙]                                                             |
|  %APPDATA%\autoclaw\Local State                                               |
|         │                                                                     |
|         ├─► os_crypt.encrypted_key (Base64)                                   |
|         │        │ Base64 解码                                                |
|         │        ▼                                                            |
|         │   [ 5 字节 "DPAPI" 魔数 ] + [ 加密的 DPAPI 原始数据块 ]              |
|         │        │ 剥离前 5 字节                                              |
|         │        ▼                                                            |
|         │   调用 Win32 API: CryptUnprotectData()                              |
|         │        │                                                            |
|         ▼        ▼                                                            |
|    【 32 字节 AES-256 主密钥 MasterKey 】 (这就是钥匙！)                       |
|                                                                               |
| ───────────────────────────────────────────────────────────────────────────── |
|                                                                               |
|  [阶段 2: 开宝箱]                                                             |
|  %APPDATA%\autoclaw\auth.json                                                 |
|         │                                                                     |
|         ├─► token: "enc:djEw..."                                              |
|         │        │ 剥除 "enc:" 前缀，Base64 解码                              |
|         │        ▼                                                            |
|         │   [ 3B 版本号 "v10" ] + [ 12B IV ] + [ 密文 Payload ] + [ 16B Tag ] |
|         │                                                                     |
|         │   装入【 32 字节 MasterKey 】，执行 AES-256-GCM 认证解密             |
|         ▼                                                                     |
|    【 得到明文: "Bearer eyJhbGciOiJIUzI1NiIsIn..." 】 (解密成功！)             |
+-------------------------------------------------------------------------------+
```

---

## 四、 第三步：第一级解密——使用 DPAPI 提取 32 字节主密钥

### 4.1 什么是 DPAPI？
DPAPI 是 Windows 内核级的安全机制（`Data Protection API`）。它的核心特性是：
- 加密时使用当前 Windows 登录用户的密码哈希和机器私钥；
- **只有在同一个 Windows 用户会话下运行的程序，才能成功调用 `CryptUnprotectData` 解密**；
- 别人把你的硬盘拆走、或者拷贝走文件，到另一台电脑上也完全解不开。

### 4.2 极其关键的“5 字节陷阱”
很多开发者第一次写解密工具时都会遇到 **`ERROR_INVALID_DATA (错误码 13)`**，原因就在于：
- Chromium 在将数据交给 Windows DPAPI 之前，硬编码加上了 5 个字节的标记：ASCII 字符串 `"DPAPI"`（十六进制：`0x44 0x50 0x41 0x50 0x49`）。
- **必须在传给 Win32 API 之前，把前 5 个字节切掉！** 剩下的数据才是 Windows DPAPI 能够识别的 `DATA_BLOB`。

### 4.3 调用 Win32 API
在 Windows 系统底层，该函数位于 `crypt32.dll`，原型如下：
```c
BOOL CryptUnprotectData(
  DATA_BLOB*      pDataIn,             // 输入：剥离 5 字节后的密文
  LPWSTR*         ppszDataDescr,       // 传 NULL
  DATA_BLOB*      pOptionalEntropy,    // 传 NULL (无额外盐)
  PVOID           pvReserved,          // 传 NULL
  CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, // 传 NULL
  DWORD           dwFlags,             // 传 0
  DATA_BLOB*      pDataOut             // 输出：32 字节 AES 密钥
);
```
调用成功后，输出的 `pDataOut` 长度刚好为 **32 字节 (256 位)**，这就是我们要用来解密 Token 的 AES-256 对称主密钥。

---

## 五、 第四步：第二级解密——使用 AES-256-GCM 还原明文 Token

拿到 32 字节主密钥后，我们来处理 `auth.json` 里的 `token`。

### 5.1 密文二进制结构剖析 (Byte-level Wire Format)
对去掉 `"enc:"` 后的字符串做 Base64 解码，得到的二进制数据内存布局如下：

```
 0                   3                   15                                   N-16              N
+-------------------+-------------------+------------------------------------+------------------+
|   版本标识 (3B)   | 初始化向量 IV (12B)|           密文主体 (L Bytes)       | 认证标签 Tag (16B)|
|   ASCII "v10"     |   96-bit Nonce    |          AES-CTR Ciphertext        |    GHASH MAC     |
+-------------------+-------------------+------------------------------------+------------------+
```

1. **版本号（字节 0 到 2，共 3 字节）**：
   固定等于 ASCII 字符串 `"v10"`（十六进制 `0x76 0x31 0x30`）。这是 Chromium 安全存储的版本代号。
2. **初始化向量 Nonce / IV（字节 3 到 14，共 12 字节）**：
   AES-GCM 标准要求使用的 96 位随机数。
3. **密文与认证标签（字节 15 到 末尾）**：
   GCM 模式下，密文主体后面紧跟着 16 字节的 GHASH Tag（认证标签）。
   在大部分密码学库中（如 Go 的 `cipher.AEAD` 或 Python 的 `AESGCM`），密文和 Tag 可以合在一起作为一个 payload 传入。

### 5.2 认证解密
将 `32 字节 MasterKey`、`12 字节 IV` 和 `密文 Payload` 送入 AES-256-GCM 解密器，解密器首先会用 Tag 校验数据完整性，校验通过后即可吐出原始 UTF-8 字符串：
`Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ...`

---

## 六、 第五步：手把手带写代码（Go、Python、PowerShell 逐行精讲）

### 6.1 Go 语言实战（零依赖单文件，推荐）

Go 语言通过标准库的 `syscall` 直接调用 Windows API，**无需安装任何 CGO 或第三方库**，编译成 exe 只有几个 MB，速度极快。

```go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// 1. 加载 Windows 底层 crypt32.dll
var (
	modcrypt32             = syscall.NewLazyDLL("crypt32.dll")
	procCryptUnprotectData = modcrypt32.NewProc("CryptUnprotectData")
)

// Windows DPAPI 专用的结构体 DATA_BLOB
type dataBlob struct {
	cbData uint32
	pbData *byte
}

// 封装 DPAPI 解密函数
func dpapiUnprotect(data []byte) ([]byte, error) {
	var inBlob dataBlob
	inBlob.cbData = uint32(len(data))
	inBlob.pbData = &data[0]

	var outBlob dataBlob
	// 调用 Windows 原生 API
	r, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r == 0 {
		return nil, fmt.Errorf("DPAPI 解密失败: %v", err)
	}
	// 释放 Win32 分配的内存
	defer syscall.LocalFree(syscall.Handle(uintptr(unsafe.Pointer(outBlob.pbData))))

	// 复制出明文结果
	res := make([]byte, outBlob.cbData)
	copy(res, unsafe.Slice(outBlob.pbData, int(outBlob.cbData)))
	return res, nil
}

func main() {
	appData := os.Getenv("APPDATA")
	localStatePath := filepath.Join(appData, "autoclaw", "Local State")
	authJsonPath := filepath.Join(appData, "autoclaw", "auth.json")

	// 步骤 A: 读 Local State 获取主密钥
	lsBytes, _ := os.ReadFile(localStatePath)
	var ls struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	json.Unmarshal(lsBytes, &ls)

	rawKey, _ := base64.StdEncoding.DecodeString(ls.OSCrypt.EncryptedKey)
	// 重点：必须切掉前 5 字节 "DPAPI"
	masterKey, err := dpapiUnprotect(rawKey[5:])
	if err != nil {
		panic(err)
	}
	fmt.Printf("[+] 成功解出 32 字节主密钥！\n")

	// 步骤 B: 读 auth.json 并解密 Token
	authBytes, _ := os.ReadFile(authJsonPath)
	var auth struct {
		Token string `json:"token"`
	}
	json.Unmarshal(authBytes, &auth)

	// 剥除 "enc:" 前缀并 Base64 解码
	encData, _ := base64.StdEncoding.DecodeString(auth.Token[4:])

	// 拆分 IV (12 字节) 与密文 (后半部分)
	iv := encData[3:15]
	payload := encData[15:]

	// 步骤 C: AES-256-GCM 解密
	block, _ := aes.NewCipher(masterKey)
	gcm, _ := cipher.NewGCM(block)
	plainToken, err := gcm.Open(nil, iv, payload, nil)
	if err != nil {
		panic("AES-GCM 解密失败: " + err.Error())
	}

	fmt.Println("==========================================")
	fmt.Printf("[+] 解密出明文 Token: %s...\n", string(plainToken[:30]))
	fmt.Println("==========================================")
}
```

---

### 6.2 Python 脚本实战（适合快速原型与脚本分析）

```python
import os
import json
import base64
import ctypes
from ctypes import wintypes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 1. 定义 Windows API DATA_BLOB 结构
class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char))
    ]

def decrypt_master_key():
    local_state_path = os.path.join(os.environ["APPDATA"], "autoclaw", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        encrypted_key_b64 = json.load(f)["os_crypt"]["encrypted_key"]

    raw = base64.b64decode(encrypted_key_b64)
    # 核心坑点：剔除前 5 字节 "DPAPI"
    blob_in_bytes = raw[5:]

    in_blob = DATA_BLOB(len(blob_in_bytes), ctypes.create_string_buffer(blob_in_bytes, len(blob_in_bytes)))
    out_blob = DATA_BLOB()

    # 调用 crypt32.dll!CryptUnprotectData
    crypt32 = ctypes.windll.crypt32
    if not crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        raise RuntimeError(f"DPAPI 失败，错误码: {ctypes.GetLastError()}")

    key = ctypes.string_at(out_blob.pbData, out_blob.cbData)
    ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    return key

def decrypt_token(master_key, enc_str):
    if not enc_str.startswith("enc:"):
        return enc_str
    
    # 剥除 enc:
    raw = base64.b64decode(enc_str[4:])
    assert raw[:3] == b"v10", "必须是 v10 封包"

    iv = raw[3:15]
    payload = raw[15:]

    # AES-256-GCM 解密
    aesgcm = AESGCM(master_key)
    plaintext = aesgcm.decrypt(iv, payload, None)
    return plaintext.decode("utf-8")

if __name__ == "__main__":
    key = decrypt_master_key()
    auth_path = os.path.join(os.environ["APPDATA"], "autoclaw", "auth.json")
    with open(auth_path, "r", encoding="utf-8") as f:
        auth_data = json.load(f)

    access_token = decrypt_token(key, auth_data["token"])
    print("[+] 成功解密出 Token:", access_token[:35], "...")
```

---

### 6.3 PowerShell 原生免装环境实战
Windows 10/11 电脑自带 PowerShell 5.1+，**一行命令即可运行，甚至连 Python 和 Go 都不用装**：

```powershell
Add-Type -AssemblyName System.Security

# 1. 读 Local State 获取主密钥
$localState = Get-Content "$env:APPDATA\autoclaw\Local State" -Raw | ConvertFrom-Json
$rawKey = [Convert]::FromBase64String($localState.os_crypt.encrypted_key)

# 剥除前 5 字节
$dpapiBlob = [byte[]]::new($rawKey.Length - 5)
[Array]::Copy($rawKey, 5, $dpapiBlob, 0, $dpapiBlob.Length)

# 使用 .NET 原生 ProtectedData 解密 DPAPI
$masterKey = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $dpapiBlob, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser
)

# 2. 解密 auth.json
$auth = Get-Content "$env:APPDATA\autoclaw\auth.json" -Raw | ConvertFrom-Json
$rawEnc = [Convert]::FromBase64String($auth.token.Substring(4))

$iv = [byte[]]::new(12)
[Array]::Copy($rawEnc, 3, $iv, 0, 12)

$cipherLen = $rawEnc.Length - 15 - 16
$cipher = [byte[]]::new($cipherLen)
[Array]::Copy($rawEnc, 15, $cipher, 0, $cipherLen)

$tag = [byte[]]::new(16)
[Array]::Copy($rawEnc, $rawEnc.Length - 16, $tag, 0, 16)

$plain = [byte[]]::new($cipherLen)
$gcm = [System.Security.Cryptography.AesGcm]::new($masterKey)
$gcm.Decrypt($iv, $cipher, $tag, $plain, $null)

$token = [System.Text.Encoding]::UTF8.GetString($plain)
Write-Host "[+] 解出 Token: $($token.Substring(0, 35))..." -ForegroundColor Green
```

---

## 七、 第六步：血泪踩坑与调试实录（常见报错与排查清单）

在实际工程落地的过程中，我们踩平了以下所有坑点，请务必注意：

### 坑 1：`GetLastError = 13` (`ERROR_INVALID_DATA`)
- **现象**：调用 `CryptUnprotectData` 返回 0，错误码 13。
- **原因**：将解码后的 `encrypted_key` 直接塞进了 API，忘记切掉前 5 个字节 `"DPAPI"`。
- **解法**：始终对数据切片 `raw[5:]`。

### 坑 2：批处理 `.bat` 在中文 Windows 下报语法错误或乱码
- **现象**：执行批处理时，cmd 打印 `'/autoclawpi' 不是内部或外部命令`，或者闪退。
- **原因**：脚本如果保存为 UTF-8 且包含中文汉字或中文注释，Windows CMD（代码页 936 / GBK）会把多字节汉字错误截断拆分，导致后面的换行符错位，拼接成错误的命令行。
- **解法**：用于生产运维的 `.bat` 启动脚本，**必须使用纯 ASCII（全英文）编写**，绝对不要写中文注释。

### 坑 3：Go 语言 `unsafe.Slice` 编译失败
- **现象**：编译提示 `cannot use outBlob.cbData (variable of type uint32) as int value in argument to unsafe.Slice`。
- **原因**：Win32 的 `cbData` 是 `uint32`，而 Go 标准库 `unsafe.Slice` 强类型要求第二个参数为 `int`。
- **解法**：显式类型转换 `int(outBlob.cbData)`。

### 坑 4：跨用户提权导致 `ERROR_ACCESS_DENIED (5)`
- **现象**：以管理员角色右键运行，或者以 Windows Service (SYSTEM 账户) 运行时无法解密。
- **原因**：DPAPI 是按**当前登录用户的 SID 隔离**的。AutoClaw 是当前普通用户启动的，只有同一普通用户权限的进程才能解开主密钥。
- **解法**：直接在普通用户权限下双击或启动代理即可，无需（且不能）以管理员提权运行。

---

## 八、 第七步：将解出的 Token 接入 OpenAI 兼容反向代理

现在你已经能在 1 秒内自动拿到 `Bearer eyJ...` 了，如何让本机所有的 Agent（Open WebUI, Claude Code, Cursor 等）都能直接用它聊天？

在反代服务中（如本项目 `D:\autoclaw2api`），我们只需做三件事：

```
+───────────────────────────────────────────────────────────────+
|                  反代服务的核心中转逻辑 (3 步)                 |
|                                                               |
| 1. 读取解密出 Token:                                          |
|    cred, _ := client.ExtractDesktopCredential()               |
|                                                               |
| 2. 伪装请求头 (三重准入判定):                                 |
|    req.Header.Set("Authorization", cred.AccessToken)          |
|    req.Header.Set("User-Agent", "Mozilla/5.0 ... AutoClaw/..")|
|    req.Header.Set("X-Request-Id", uuid.New().String())        |
|    req.Header.Set("X-Request-Model", "openrouter_glm-5.2")    |
|                                                               |
| 3. 请求体补齐 System Banner (防上游 400 校验):                |
|    "You are a personal assistant running inside OpenClaw..."  |
+───────────────────────────────────────────────────────────────+
```

整个过程全自动闭环，外部客户端只需连接：
- **Base URL**：`http://127.0.0.1:8787/v1`
- **Model**：`glm-5.2` 或 `glm-5-turbo`
- **API Key**：`your-api-key` (你设置的本地保护密钥)

大功告成！你拥有了一个**自动从本地客户端取凭据、自动轮转刷新、完全兼容 OpenAI 接口标准的本地 AI 代理网关**！
