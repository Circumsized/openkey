# AutoClaw 桌面端 (1.18.4) 本地凭据两级加密与逆向解密工程技术规约

---

## 摘要 (Abstract)

本文档系统化阐述针对 Windows 平台下 AutoClaw 桌面端（Electron 33.4.11 / Chromium 128 内核）本地持久化凭据机制的逆向分析结论与密码学解密规范。

桌面端利用操作系统内核安全子系统与现代对称认证加密算法构建了**两级密钥防护架构**：
1. **传输与会话层凭据保护**：基于 **AES-256-GCM**（Galois/Counter Mode）算法对访问令牌（`access_token`）与刷新令牌（`refresh_token`）进行对称加密并生成带认证标签的密文（存储前缀标为 `enc:v10...`）；
2. **密钥管理层保护**：加密上述会话令牌所需的 256 位对称主密钥（Master Key），本身不以明文存储，而是托管于 Windows 系统的 **DPAPI (Data Protection API)**，绑定当前登录用户的本地安全标识符（SID）与密码派生凭据环。

通过在同一用户安全上下文中调用本地 Win32 系统安全接口，反代代理服务可实现 **1 秒级无感知静默解密**，完全废除传统抓包与人工干预流程。

---

## 一、 整体密码学架构与解密状态机

```
                      [ AutoClaw 客户端登录成功 ]
                                  │
          ┌───────────────────────┴───────────────────────┐
          ▼                                               ▼
[ 32 字节随机主密钥 MasterKey ]               [ 明文 JWT Token: Bearer eyJ... ]
          │                                               │
          ▼ (DPAPI: CryptProtectData)                     ▼ (AES-256-GCM 加密)
[ 密文: "DPAPI" + Win32_BLOB ]                [ "v10" + IV(12B) + Ciphertext + Tag(16B) ]
          │ (Base64 编码)                                 │ (Base64 编码 + "enc:" 前缀)
          ▼                                               ▼
%APPDATA%\autoclaw\Local State               %APPDATA%\autoclaw\auth.json
(os_crypt.encrypted_key)                     (token / refreshToken)
```

### 解密反向状态机 (Decryption State Machine)

```
[ 触发自动提取 ]
       │
       ├─► 阶段 1: 定位并校验 %APPDATA%\autoclaw\Local State
       │     └─► JSON 解析提取 os_crypt.encrypted_key
       │     └─► Base64 解码 ──► 校验前 5 字节魔数是否为 ASCII "DPAPI"
       │     └─► 剥离前 5 字节 (offset 5..end)
       │     └─► 调用 Windows crypt32.dll!CryptUnprotectData
       │     └─► 内存安全解出 32 字节 (256-bit) 原始 MasterKey
       │
       └─► 阶段 2: 定位并校验 %APPDATA%\autoclaw\auth.json
             └─► JSON 解析提取 token / refreshToken (必须包含 "enc:" 前缀)
             └─► 剥离前缀 "enc:" (4 字节)
             └─► Base64 解码得到二进制密文数据流
             └─► 校验前 3 字节协议版本号是否为 ASCII "v10"
             └─► 切片拆分:
             │     ├─ Nonce/IV : offset [3 : 15]   (12 字节 = 96 位)
             │     ├─ Payload  : offset [15 : -16] (可变长密文字节)
             │     └─ Auth Tag : offset [-16 :]    (16 字节 = 128 位)
             └─► 实例化 AES-256-GCM 算法器，装载 MasterKey
             └─► 校验 GHASH Tag 并认证解密密文 Payload
             └─► 输出明文 UTF-8 字符串: "Bearer eyJhbGciOiJ..." (长度 ~386 字符)
```

---

## 二、 逐字节内存布局与报文协议标准 (Wire Format)

### 1. 主密钥包 (`Local State` -> `os_crypt.encrypted_key`)

对 `encrypted_key` 字段进行 Base64 解码后，二进制数据结构严格遵循下表：

| 字节偏移 (Offset) | 字段名称 (Field) | 长度 (Length) | 编码/格式 | 描述与约束 |
| :--- | :--- | :--- | :--- | :--- |
| `0x00 .. 0x04` | `MagicHeader` | 5 字节 | ASCII | 必须恒等于 `0x44 0x50 0x41 0x50 0x49` (`"DPAPI"`) |
| `0x05 .. 0x08` | `dwVersion` | 4 字节 | uint32 (LE) | DPAPI 结构体内部版本号（通常为 `0x00000001`） |
| `0x09 .. 0x18` | `guidProvider`| 16 字节 | GUID | 负责保护数据的密码提供程序标识符 |
| `0x19 .. 0x28` | `guidMasterKey`| 16 字节 | GUID | 指向 `%APPDATA%\Microsoft\Protect\{SID}` 下对应的主密钥文件标识 |
| `0x29 .. End` | `EncryptedData`| 可变长 | 二进制 | 加密后的对称密钥实体与 HMAC 完整性校验信息 |

> **关键实现准则 (Critical Rule)**：
> 调用 `CryptUnprotectData` 时，传入的 `DATA_BLOB.pbData` 必须从**偏移量 5**（即跳过 `"DPAPI"` 5 字节）开始切片，`cbData` 必须等于 `len - 5`。若直接将含 `"DPAPI"` 的完整字节流传入，Win32 API 将抛出 `ERROR_INVALID_DATA (13)` 异常。

---

### 2. 会话令牌密文包 (`auth.json` -> `token` / `refreshToken`)

字符串必须以 `enc:` 开头。去除该 4 字节前缀后，剩余字符串进行标准 Base64 解码，二进制字节流结构如下：

```
+---------------+-----------------+---------------------------------+-----------------+
| Magic (3B)    | Nonce / IV (12B)| Encrypted Payload (L Bytes)     | Auth Tag (16B)  |
| "v10"         | 96-bit Random   | AES-CTR Mode Ciphertext         | GHASH Tag       |
+---------------+-----------------+---------------------------------+-----------------+
 0               3                 15                                15 + L            31 + L
```

详细字段解析：

| 字段 | 偏移区间 | 长度 | 密码学语义 | 校验约束 |
| :--- | :--- | :--- | :--- | :--- |
| **Version** | `[0 : 3]` | 3 字节 | safeStorage 算法版本标识 | 严格等于 `0x76 0x31 0x30` (ASCII `"v10"`) |
| **Nonce / IV** | `[3 : 15]` | 12 字节 | GCM 模式随机初始化向量 | 每条记录独立生成，禁止重用 |
| **Ciphertext** | `[15 : N-16]` | $N - 31$ 字节 | AES-CTR 密文正文 | 明文经流式加密后生成的密文块 |
| **Tag** | `[N-16 : N]` | 16 字节 | Galois 消息完整性认证标签 (MAC) | 保证密文在存储期间未遭受任何比特翻转篡改 |

---

## 三、 形式化数学定义 (Formal Cryptographic Definitions)

### 1. 密钥解封装 (Key Decapsulation)

定义 $B_{\text{b64}}$ 为 `Local State` 中提取的 Base64 字符串：

$$B = \text{Base64-Decode}(B_{\text{b64}})$$

断言：

$$B[0:5] = \text{"DPAPI"}$$

主密钥 $K_{\text{AES}}$ 满足：

$$K_{\text{AES}} = \text{Win32-DPAPI-Unprotect}(B[5:]) \quad \text{其中} \quad |K_{\text{AES}}| = 32 \text{ bytes (256 bits)}$$

---

### 2. 认证解密 (Authenticated Decryption)

定义字符串 $S = \text{"enc:"} \mathbin{\Vert} D_{\text{b64}}$。

解密前置预处理：

$$D = \text{Base64-Decode}(D_{\text{b64}})$$

$$|D| \ge 31 \quad \land \quad D[0:3] = \text{"v10"}$$

切片分配：

$$IV = D[3:15] \in \{0, 1\}^{96}$$

$$C = D[15 : |D|-16]$$

$$T = D[|D|-16 : |D|] \in \{0, 1\}^{128}$$

执行 AES-256-GCM 认证解密函数 $\mathcal{D}_{\text{GCM}}$：

$$P = \mathcal{D}_{\text{GCM}}(K_{\text{AES}}, IV, C, T, AAD=\emptyset)$$

若 $T \neq \text{GHASH}_{H}(C \mathbin{\Vert} \text{len}(AAD) \mathbin{\Vert} \text{len}(C)) \oplus E_{K_{\text{AES}}}(IV \mathbin{\Vert} 0^{31}1)$，则立即抛出认证失败异常并拒绝返回任何明文。

---

## 四、 核心逆向依据（Electron 33 内部源码映射）

在 AutoClaw `D:\autoclaw\resources\app.asar` 的核心打包模块中，已逆向提取出官方原生写入逻辑：

```javascript
// 逆向自 app.asar/main.js
const { safeStorage } = require("electron");

function encryptSecret(plaintext) {
  // 当开发者开启了免密绕过标志时的旁路
  if (process.env.AUTOCLAW_DEV_PLAINTEXT_AUTH === "1") {
    return plaintext;
  }
  // 正常生产模式：调用 safeStorage 并打上 enc: 标识
  const encrypted = safeStorage.encryptString(plaintext);
  return "enc:" + encrypted.toString("base64");
}
```

Electron `safeStorage.encryptString()` 在 Windows 平台的底层实现直接调用 Chromium 的 `os_crypt::EncryptString`，这直接证实了本文档定义的 `v10` 两级加密规范的绝对准确性。
