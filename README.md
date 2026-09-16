# OpenKey: AutoClaw 桌面端底层凭据逆向工程与自动化解密算法系统

[![Security Standard](https://img.shields.io/badge/Security-DPAPI%20%2B%20AES--256--GCM-blue.svg)](#)
[![Electron Target](https://img.shields.io/badge/AutoClaw-v1.18.4%20(Electron%2033)-success.svg)](#)
[![Zero-Dependency](https://img.shields.io/badge/Go%20%26%20PowerShell-Zero%20Dependency-brightgreen.svg)](#)
[![Compliance](https://img.shields.io/badge/Zero--Credential-Audited-green.svg)](#)

---

## 核心论述与工程定论

* **加密方式**：桌面端使用 Windows 系统的 **DPAPI (Data Protection API)** 结合 **AES-256-GCM** 算法对 Token 进行了本地加密保护（持久化密文具有固定前缀 `enc:`，内部封包版本为 `v10`）。
* **自动化解密**：我们的后台服务直接调用 Windows 系统的本地安全解密接口（`crypt32.dll!CryptUnprotectData`），剥离魔数后自动解出 32 字节主密钥，并对 `auth.json` 里的 `access_token` 和 `refresh_token` 进行无缝的认证解密。
* **极速体验**：因此，**只要你的 AutoClaw 客户端在电脑上处于已登录状态，程序就能在 1 秒内全自动提取出完整 Token！** 彻底废弃繁琐的人工抓包、控制台请求头截获与验证码等待环节！

---

## 一、 系统化工程文档体系 (Documentation Matrix)

整个 `openkey/` 技术库按照 RFC 标准工程规范建立了系统化的文档体系：

```
openkey/
├── README.md                                 # [本文件] 体系总览与快速导航
├── TUTORIAL_FROM_ZERO.md                     # ★★★【零基础新手教程】从0开始彻底搞懂解密原理与实战手把手开发
├── ALGORITHM_GUIDE.md                        # 技术白皮书：核心架构、两级状态机与数学模型
├── DECRYPTION_SPEC.md                        # 逆向工程规约：逐字节二进制报文协议 (Wire Format)
├── extract_token.bat                         # Windows 桌面一键解密提取工具 (纯 ASCII 无乱码)
├── decryptor.go                              # 工业级 Go 独立参考实现 (零第三方依赖，纯 Win32 syscall)
├── decryptor.py                              # Python 强类型参考实现 (ctypes + cryptography)
├── docs/
│   ├── ARCHITECTURE_AND_CRYPTO_SPEC.md       # 深度规范：形式化数学定义、AEAD 鉴别与安全模型
│   ├── ERROR_CODES_AND_TROUBLESHOOTING.md    # 诊断矩阵：Win32/NTSTATUS 错误码全集与排错流程
│   └── TEST_VECTORS_AND_VERIFICATION.md      # 测试向量：RFC 规范确定性测试套件 (零真实凭据)
└── src/
    └── powershell/
        └── Decrypt-AutoClawToken.ps1         # Windows 原生 PowerShell 实现 (.NET 原生，免安装环境)
```

---

## 二、 核心密码学模型 (Cryptographic Hierarchy)

```
========================================================================================
                                   两级加密防护体系
========================================================================================

[第一级：系统内核安全隔离 (Key Management Layer)]
  Windows LSA / DPAPI
    └─► 输入: %APPDATA%\autoclaw\Local State -> os_crypt.encrypted_key (Base64)
    └─► 协议规约: 严格剥除前 5 字节 ASCII "DPAPI" 魔数头 (避免 Code 13 错误)
    └─► Win32 API: crypt32.dll -> CryptUnprotectData(&blob_stripped)
    └─► 产出: 32 字节 (256-bit) 原始对称主密钥 MasterKey

[第二级：会话令牌认证加密 (Credential Layer)]
  AES-256-GCM (Authenticated Encryption with Associated Data)
    └─► 输入: %APPDATA%\autoclaw\auth.json -> token / refreshToken
    └─► 协议规约: 剥除 "enc:" 前缀 -> Base64 解码 -> 校验前 3 字节 "v10"
    └─► 内存切片拆分:
          ├─ IV (Nonce) : offset [3 : 15]   (12 字节 = 96 位随机数)
          ├─ Ciphertext : offset [15 : -16] (流式对称密文正文)
          └─ Auth Tag   : offset [-16 : ]   (16 字节 = 128 位 GHASH 鉴别标签)
    └─► AEAD 认证解密: 校验 Tag 一致性，防止密文翻转与中间人篡改
    └─► 产出: 完整可用明文 JWT 令牌 ("Bearer eyJhbGciOiJ...")
========================================================================================
```

---

## 三、 多语言参考实现矩阵

为适应不同的生产部署、运维流水线或调试场景，本项目提供三种原生实现：

| 实现方式 | 脚本路径 | 依赖环境 | 特性与优势 |
| :--- | :--- | :--- | :--- |
| **Go 独立实现** | `openkey/decryptor.go` | Go 1.18+（或单文件编译后二进制） | **零第三方外部依赖**，纯 Windows 原生 syscall 实现，毫秒级直接输出 |
| **Windows 批处理**| `openkey/extract_token.bat` | Windows 10/11 开箱即用 | **桌面双击即用**，纯 ASCII 编码杜绝乱码，带彩色高亮交互 |
| **PowerShell 原生**| `openkey/src/powershell/Decrypt-AutoClawToken.ps1`| Windows PowerShell 5.1+ / PS Core | **免安装任何环境**，直接调用 .NET `ProtectedData` 与 `AesGcm` |
| **Python 标准实现**| `openkey/decryptor.py` | Python 3.8+ (`cryptography`) | 强类型注解，支持作为独立 CLI 或导入 Python 自动化流水线 |

---

## 四、 快速使用与独立验证

### 1. Windows 桌面双击提取 (最傻瓜)
打开文件资源管理器进入 `D:\autoclaw2api\openkey\`，直接双击运行：
👉 **`extract_token.bat`**

### 2. 命令行 Go 运行 (免配置外部包)
```cmd
cd /d D:\autoclaw2api\openkey
D:\tools\go\bin\go.exe run decryptor.go
```

### 3. 原生 PowerShell 运行 (无需任何开发环境)
```powershell
powershell -ExecutionPolicy Bypass -File D:\autoclaw2api\openkey\src\powershell\Decrypt-AutoClawToken.ps1
```

### 4. Python 运行
```cmd
cd /d D:\autoclaw2api\openkey
python decryptor.py
```

---

## 五、 安全审计与合规说明 (Compliance)

1. **凭据零残留 (Zero Hardcoding)**：
   本工程库的所有代码、示例、测试向量及文档中，**严禁且未硬编码任何可用的生产环境凭据字面量**。所有令牌均在运行期间从本地安全沙盒动态解出并留在临时内存中。
2. **安全路径防穿越 (Path Traversal Hardened)**：
   所有涉及文件 I/O 的路径均实施了 `filepath.Clean`、`GetFullPath` 及目录白名单边界强校验，禁止 `../` 越权访问。
3. **内存即用即弃**：
   解密调用完成后，DPAPI 分配的底层缓冲区通过 `LocalFree` 显式销毁，杜绝敏感密钥在进程内存中长期驻留。
