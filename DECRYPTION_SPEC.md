# AutoClaw 桌面端凭据加解密算法与逆向工程规范

> **文档版本**: 1.0.0  
> **适用目标**: AutoClaw 桌面客户端 (Electron 架构，Windows 平台，v1.17.x ~ v1.18.x)  
> **算法体系**: Windows DPAPI (Data Protection API) + AES-256-GCM (Chromium os_crypt v10 规范)

---

## 1. 架构总览与加密背景

AutoClaw 桌面端基于 Electron 框架构建，其用户登录凭证（Access Token、Refresh Token）采用 Chromium 体系推荐的 `safeStorage` 机制进行落盘加密。

为了防止恶意软件在无授权情况下直接窃取文本文件中的 JWT 令牌，客户端在持久化至 `%APPDATA%\autoclaw\auth.json` 或 `token-cache.json` 时，引入了**两级密钥防护结构**：

```
+-----------------------------------------------------------------------+
| 阶段一：主密钥派生 (Master Key Derivation)                              |
|                                                                       |
| %APPDATA%\autoclaw\Local State                                        |
|     │                                                                 |
|     ▼ os_crypt.encrypted_key                                          |
| [Base64 字符串]                                                        |
|     │                                                                 |
|     ▼ Base64 解码                                                     |
| [5 字节 "DPAPI" 标识] + [Windows DPAPI 加密数据块]                      |
|                               │                                       |
|                               ▼ Windows CryptUnprotectData (DPAPI)   |
|                 [32 字节 AES-256 对称主密钥 Master Key]                 |
+-----------------------------------------------------------------------+
                                │
                                ▼
+-----------------------------------------------------------------------+
| 阶段二：载荷解密 (Payload Decryption)                                  |
|                                                                       |
| %APPDATA%\autoclaw\auth.json                                          |
|     │                                                                 |
|     ▼ token / refreshToken                                            |
| ["enc:" + Base64 密文]                                                |
|     │                                                                 |
|     ▼ 剥离 "enc:" 前缀并 Base64 解码                                    |
| [3 字节 "v10"] + [12 字节 IV] + [密文数据 Ciphertext] + [16 字节 Tag]   |
|                               │                                       |
|                 Master Key ───┤                                       |
|                               ▼ AES-256-GCM 解密                      |
|          [明文 JWT 令牌: "Bearer eyJhbGciOiJIUzI1Ni..."]               |
+-----------------------------------------------------------------------+
```

---

## 2. 阶段一：主密钥提取算法 (DPAPI Unprotect)

### 2.1 凭据源定位
* **文件路径**: `%APPDATA%\autoclaw\Local State`
* **编码格式**: JSON
* **目标键**: `.os_crypt.encrypted_key`

### 2.2 解密流程
1. **读取文件**: 读取 `Local State` 文件并解析 JSON 结构。
2. **Base64 解码**: 对 `state.os_crypt.encrypted_key` 执行标准 Base64 解码，得到字节数组。
3. **魔数校验**: 校验字节数组前 5 字节，必须严格等于 ASCII 字符串 `"DPAPI"` (`0x44 0x50 0x41 0x50 0x49`)。
4. **截取数据块**: 剥离前 5 字节，剩余部分为合法的 Windows DPAPI `DATA_BLOB`。
5. **Win32 API 调用**:
   调用 `crypt32.dll` 导出的 `CryptUnprotectData` 函数：
   ```c
   BOOL CryptUnprotectData(
       DATA_BLOB*      pDataIn,             // 输入：剥离后的 DPAPI 数据块
       LPWSTR*         ppszDataDescr,       // NULL
       DATA_BLOB*      pOptionalEntropy,    // NULL (Electron 未提供额外熵)
       PVOID           pvReserved,          // NULL
       CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, // NULL
       DWORD           dwFlags,             // 0
       DATA_BLOB*      pDataOut             // 输出：解密后的主密钥 (32 字节)
   );
   ```
6. **资源释放**: 提取 `pDataOut` 中的 32 字节 AES 密钥后，必须使用 `LocalFree` 释放由系统分配的内存空间。

---

## 3. 阶段二：Token 密文解密算法 (AES-256-GCM)

### 3.1 凭据源定位
* **主文件**: `%APPDATA%\autoclaw\auth.json`
* **备用文件**: `%APPDATA%\autoclaw\token-cache.json`
* **目标键**: `.token` (Access Token) 与 `.refreshToken` (Refresh Token)

### 3.2 密文封装格式 (Wire Format)
读取到的字符串以 `enc:` 前缀起始，其内部二进制包结构定义如下：

| 字节偏移 (Offset) | 长度 (Length) | 字段名称 | 说明 |
| :--- | :--- | :--- | :--- |
| `0 .. 3` | 3 字节 | Version Prefix | 必须为固定 ASCII 字符串 `"v10"` (`0x76 0x31 0x30`) |
| `3 .. 15` | 12 字节 | Nonce / IV | GCM 模式所需的 96-bit 随机初始化向量 |
| `15 .. (Len - 16)` | 可变长度 | Ciphertext | AES-256 密文本体 |
| `(Len - 16) .. Len` | 16 字节 | Auth Tag | GCM 认证标签 (GHASH Tag，用于防篡改校验) |

### 3.3 解密计算步骤
1. **前缀剥离**: 若字符串以 `enc:` 开头，去除该 4 字节前缀；若无前缀，则表示为未加密的明文 Token，直接返回。
2. **Base64 解码**: 将剥离后的字符串解码为原始字节流。
3. **长度与版本断言**:
   - 字节流总长度必须 $\ge 31$ 字节 ($3 + 12 + 16$)。
   - 前 3 字节必须等于 `"v10"`。
4. **拆分组件**:
   - 提取 `IV = raw[3:15]` (12 字节)。
   - 提取 `Payload = raw[15:]`（在 Go/Python 的标准 AEAD 实现中，通常将 `Ciphertext + Tag` 合并作为密文载荷输入）。
5. **执行 AEAD 解密**:
   - 实例化 AES-256-GCM 密码器，输入阶段一获取的 32 字节 Master Key。
   - 附加验证数据 (AAD) 设为空 (`nil` / `None`)。
   - 执行 `Open` / `decrypt` 操作，若 Tag 校验失败则抛出完整性破坏异常。
6. **Token 规范化**:
   - 解密结果解码为 UTF-8 字符串。
   - 检查字符串前缀，若无 `Bearer ` 前缀则统一补齐为 `Bearer <JWT>` 规范格式。

---

## 4. 关键安全与边界约束

1. **操作系统权限边界**:
   DPAPI 基于当前 Windows 登录用户的本地主密钥（通过 Windows 登录密码与用户 SID 加密）进行防护。因此，解密进程必须运行在**与运行 AutoClaw 桌面端相同的 Windows 用户上下文**下。
2. **路径穿越防御**:
   在读取 `%APPDATA%\autoclaw` 文件时，所有路径必须经过 `filepath.Clean` / `os.path.realpath` 规范化，断言其根目录位于允许的白名单范围内，杜绝 `..` 越权访问。
3. **凭据零落地原则**:
   解密后的明文 JWT 令牌仅驻留于代理服务的易失性内存中，绝不输出到日志文件或外传，确保本机其他 Agent 调用的安全性。
