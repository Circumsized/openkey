# AutoClaw 凭据解密故障排查与 Win32 / 密码学错误码诊断矩阵

---

## 错误代码诊断全集

下表总结了在针对 AutoClaw 桌面端进行本地 DPAPI 提取与 AES-256-GCM 解密过程中，可能遭遇的所有系统级、网络级与密码学异常：

| 错误代码 / 标识 | 错误描述 (Description) | 发生阶段 | 根因分析 (Root Cause) | 解决方案 (Resolution) |
| :--- | :--- | :--- | :--- | :--- |
| **`ERROR_INVALID_DATA (13)`** | 数据的格式不正确 | 阶段 1: DPAPI 解密 | 将 Base64 解码后的 `encrypted_key` 直接传入 `CryptUnprotectData`，未剔除前 5 字节 ASCII `"DPAPI"` 魔数头 | 确保传入的缓冲指针为 `bytes[5:]`，长度为 `len - 5` |
| **`ERROR_ACCESS_DENIED (5)`** | 拒绝访问 | 阶段 1: DPAPI 解密 | 反代服务运行在与 AutoClaw 客户端**不同的 Windows 用户会话**下（如以 SYSTEM 服务、另一本地用户运行） | 必须保证解密进程运行在启动 AutoClaw 的同一交互式用户上下文（同一 SID） |
| **`NTE_BAD_KEYSET (0x80090016)`** | 键集不存在 | 阶段 1: DPAPI 解密 | 用户的 `%APPDATA%\Microsoft\Protect\{SID}` 主密钥环被破坏、删除，或通过 RDP 切换用户导致 LSA 凭据隔离 | 重启 AutoClaw 客户端触发其重新生成本地保护密钥 |
| **`ERROR_INVALID_PARAMETER (87)`** | 参数错误 | 阶段 1: DPAPI 解密 | `DATA_BLOB` 结构体的 `cbData` 长度与实际传入的字节流指针不匹配，或内存指针为空 | 检查 `unsafe.Pointer` 强转逻辑，确保内存切片已正确分配并连续 |
| **`AES-GCM Authentication Failed`** | 消息完整性认证失败 (Tag Mismatch) | 阶段 2: GCM 解密 | 1. 主密钥不正确；2. 密文字节遭外部篡改；3. 截取的末尾 16 字节 Tag 偏移有误 | 校验密文字节流长度必须 $\ge 31$ 字节；确保 IV 为前 12 字节，Tag 为最后 16 字节 |
| **`Invalid Version Header`** | 未知安全存储版本 | 阶段 2: 结构校验 | 密文字节流前 3 字节不是 ASCII `"v10"` | 校验前 3 字节，若不是 `v10` 说明客户端使用了非 Chromium 标准安全存储（如开发绕过模式） |
| **`ERROR_SHARING_VIOLATION (32)`** | 进程无法访问文件，因为文件正由另一进程使用 | 文件读取阶段 | AutoClaw 客户端正在写入 `auth.json` 或持有独占写入锁 | 以非阻塞共享读取模式打开文件（Windows `FILE_SHARE_READ \| FILE_SHARE_WRITE`） |
| **`JSON Unmarshal Error`** | 反序列化格式错误 | 数据解析阶段 | `auth.json` 写入到一半发生断电或崩溃，导致 JSON 报文截断 | 检测备用文件 `auth.json.backup` 或 `token-cache.json` 进行平滑回退容灾 |

---

## 常见诊断流程图 (Troubleshooting Flowchart)

```
[开始解密]
   │
   ├─► 检查 APPDATA 环境变量是否存在？
   │      ├─ 否 ──► 抛出 EnvironmentError (检查当前运行用户权限)
   │      └─ 是 ──► 继续
   │
   ├─► %APPDATA%\autoclaw\Local State 是否存在？
   │      ├─ 否 ──► 客户端从未在此机器上运行或安装目录异常
   │      └─ 是 ──► 读取并解码 os_crypt.encrypted_key
   │
   ├─► 解码后的 encrypted_key 是否以 "DPAPI" 开头？
   │      ├─ 否 ──► 非预期的 Chromium 版本或被第三方加密篡改
   │      └─ 是 ──► 剥离前 5 字节传入 Win32 DPAPI
   │
   ├─► CryptUnprotectData 返回值判断
   │      ├─ 失败 (Code 13) ──► 必定是魔数未剥离干净
   │      ├─ 失败 (Code 5)  ──► 进程跨用户越权，切换至客户端同用户运行
   │      └─ 成功 ──────────► 获得 32 字节 MasterKey
   │
   └─► auth.json 中的 token 是否以 "enc:" 开头？
          ├─ 否 ──► 客户端当前处于开发者明文模式 (AUTOCLAW_DEV_PLAINTEXT_AUTH=1)，直接使用
          └─ 是 ──► 剥离 enc: 执行 Base64，校验 "v10" 并调用 AES-256-GCM 完成解密
```
