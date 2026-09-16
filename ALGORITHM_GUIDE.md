# AutoClaw 桌面端 1 秒自动化凭据解密与提取技术白皮书

---

## 核心结论与技术摘要

* **加密方式**：桌面端使用 Windows 系统的 **DPAPI (Data Protection API)** 结合 **AES-256-GCM** 算法对 Token 进行了本地加密保护（前缀为 `enc:`）。
* **自动化解密**：我们的后台服务直接调用 Windows 系统的本地解密接口，自动解出主密钥，并对 `auth.json` 里的 `access_token` 和 `refresh_token` 进行无缝解密。
* **极速体验**：因此，只要你的 AutoClaw 客户端在电脑上处于已登录状态，程序就能在 **1 秒内全自动提取出完整 Token**！彻底告别手工抓包、请求头截取与复杂的会话查找！

---

## 一、 为什么桌面端需要两级加密？

在 AutoClaw 桌面端（基于 Electron 33 / Chromium 内核）的架构中，用户的 Access Token 具备直接调用上游大模型 API 的全部权限。如果直接以明文存放在硬盘的 JSON 文件中，极易被非受信的第三方进程窃取。

为此，官方引入了基于 Chromium 规范的 `safeStorage`（底层为 `os_crypt`）保护体系：

```
+-----------------------------------------------------------------------------+
|                          AutoClaw 桌面端加密链路                             |
|                                                                             |
|  [明文 Token: Bearer eyJ...]                                                |
|            │                                                                |
|            ▼ (由 safeStorage / AES-256-GCM 执行加密)                         |
|  [密文字节流: "v10" (3B) + IV (12B) + Ciphertext + Tag (16B)]                 |
|            │                                                                |
|            ▼ (Base64 编码并加上 "enc:" 前缀)                                  |
|  [持久化字符串: "enc:djEw..." 写入 auth.json / token-cache.json]              |
+-----------------------------------------------------------------------------+
```

而用于加密该密文的 **32 字节 AES-256 对称主密钥 (Master Key)**，自身不能明文保存在磁盘上，因此被交由 **Windows 操作系统的 DPAPI 机制** 进行二次封锁，保存在 `Local State` 文件中。

---

## 二、 自动化解密算法完整数学与工程拆解

整个自动化解密链条分为两个不可分割的阶段：

### 阶段 1：通过 Windows DPAPI 接口还原 32 字节主密钥

1. **凭据文件源**：
   定位当前登录用户的应用数据目录：`%APPDATA%\autoclaw\Local State`。
2. **提取密文主密钥**：
   解析 JSON，定位键值路径：`os_crypt.encrypted_key`。
3. **剥离 DPAPI 协议头**：
   对其进行 Base64 解码。此时得到的字节数组前 5 字节必定是固定 ASCII 标识 `"DPAPI"`（十六进制 `0x44 0x50 0x41 0x50 0x49`）。
   > **关键技术陷阱**：必须在调用 Win32 API 之前，精确剥离这 5 个字节！若将包含 `"DPAPI"` 的完整数据块直接传入系统 API，Windows 将抛出 `ERROR_INVALID_DATA (错误码 13)`。
4. **Win32 本地解密调用**：
   将剥离后的二进制数据封装为 `DATA_BLOB` 结构，直接调用 Windows 内核动态链接库 `crypt32.dll` 导出的 `CryptUnprotectData` 接口：
   $$\text{MasterKey} = \text{CryptUnprotectData}(\text{Blob}_{\text{stripped}})$$
   由于 DPAPI 绑定了当前 Windows 用户的登录凭据与私钥环，系统将在微秒级时间内自动解密，输出长度为 **32 字节（256 位）的 AES 原始主密钥**。

---

### 阶段 2：通过 AES-256-GCM 还原明文 Access / Refresh Token

1. **凭据文件源**：
   定位 `%APPDATA%\autoclaw\auth.json`（或 `token-cache.json`）。
2. **提取密文载荷**：
   读取键值 `token` 与 `refreshToken`。典型特征是以 `enc:` 开头。
3. **格式反序列化**：
   - 剥除字符串前缀 `"enc:"`（4 字节）。
   - 将剩余字符串进行标准 Base64 解码，还原二进制报文。
4. **二进制结构校验与字段切片**：
   报文总长度必须满足 $\ge 31$ 字节，其二进制内存布局如下：

   | 偏移区间 | 长度 | 含义 | 校验与处理 |
   | :--- | :--- | :--- | :--- |
   | `[0 : 3]` | 3 字节 | 版本标识 (Version) | 必须严格等于 ASCII 字符串 `"v10"` |
   | `[3 : 15]` | 12 字节 | 初始化向量 (Nonce / IV) | GCM 模式专属随机向量，传入解密器 |
   | `[15 : end]` | 剩余字节 | 密文载荷 (Ciphertext + Tag) | 包含实际加密正文与末尾 16 字节 GHASH 防篡改认证标签 |

5. **执行 AEAD 对称解密**：
   - 实例化 AES-256-GCM 密码机，装载阶段 1 获得的 32 字节 Master Key。
   - 输入 12 字节 IV 与密文载荷，AAD 设为空。
   - 执行认证解密操作，系统将校验 Tag 的合法性（确保文件未被外部恶意篡改），校验通过后输出原始 UTF-8 字节流。
6. **规范化输出**：
   解出的 Access Token 为合法 JWT 字符串，若缺少 `Bearer ` 则前置自动补齐，成为可以直接赋给 HTTP `Authorization` 头的标准凭证！

---

## 三、 本目录（openkey/）下提供的完整工具矩阵

为满足工程集成与独立审计需求，`openkey/` 目录下提供了完整的跨语言交付矩阵：

1. **`openkey/DECRYPTION_SPEC.md`**：
   详细的二进制报文规范、偏移量字典与架构白皮书。
2. **`openkey/decryptor.go`**：
   纯 Go 语言官方标准库 + Windows syscall 实现，**零第三方依赖**。编译后为单文件二进制，可在无 Python 环境下毫秒级极速提取。
3. **`openkey/decryptor.py`**：
   Python 3 独立参考实现，利用 `ctypes` 原生直调 Windows API，可作为独立 CLI 工具执行，亦可作为模块被其他 Python 自动化流水线直接 import。
4. **`openkey/extract_token.bat`**：
   Windows 用户专属双击启动批处理，1 秒内直接在控制台输出当前 AutoClaw 桌面端账号、用户手机、Access Token 与有效长度。

---

## 四、 极速上手验证

在控制台或终端运行以下命令，即可亲眼见证 1 秒解密：

```bash
# 方式 A：Go 语言极速运行（推荐）
cd D:\autoclaw2api\openkey
D:\tools\go\bin\go.exe run decryptor.go

# 方式 B：Python 语言运行
python D:\autoclaw2api\openkey\decryptor.py
```
