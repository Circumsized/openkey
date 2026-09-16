#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AutoClaw 桌面端凭据本地解密工具 (Python 3 参考实现)

核心原理:
1. 从 %APPDATA%/autoclaw/Local State 读取 base64 编码的 encrypted_key
2. 剥除前 5 字节 "DPAPI" 标识，调用 Windows CryptUnprotectData 获取 32 字节 Master Key
3. 从 %APPDATA%/autoclaw/auth.json 读取 enc: 开头的密文字符串
4. 剥除 "enc:" 前缀，Base64 解码得到 v10 + IV(12) + Ciphertext + Tag(16)
5. 使用 AES-256-GCM 解密还原明文 JWT 令牌 (Bearer eyJ...)
"""

import os
import sys
import json
import base64
import ctypes
from ctypes import wintypes
from typing import Dict, Any, Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


def _win_dpapi_decrypt(encrypted_blob: bytes) -> bytes:
    """使用 Windows DPAPI 解密数据块"""
    if sys.platform != "win32":
        raise OSError("DPAPI 解密仅支持 Windows 平台")

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    in_blob = DATA_BLOB()
    in_blob.cbData = len(encrypted_blob)
    in_blob.pbData = ctypes.cast(
        ctypes.create_string_buffer(encrypted_blob),
        ctypes.POINTER(ctypes.c_byte)
    )

    out_blob = DATA_BLOB()

    # BOOL CryptUnprotectData(...)
    ret = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    )

    if not ret:
        err = ctypes.GetLastError()
        raise RuntimeError(f"CryptUnprotectData 调用失败, GetLastError={err}")

    try:
        decrypted_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return decrypted_bytes
    finally:
        kernel32.LocalFree(out_blob.pbData)


def get_safe_appdata_dir() -> str:
    """安全解析并校验 AutoClaw 本地数据目录，防止路径穿越"""
    appdata = os.environ.get("APPDATA")
    if not appdata:
        raise ValueError("APPDATA 环境变量未设置")

    base_dir = os.path.realpath(os.path.abspath(appdata))
    target_dir = os.path.realpath(os.path.join(base_dir, "autoclaw"))

    # 安全断言：目标目录必须在 APPDATA 下
    if not target_dir.startswith(base_dir):
        raise ValueError("检测到非法路径穿越")

    return target_dir


def read_safe_file(directory: str, filename: str) -> bytes:
    """在受保护目录下安全读取单个文件"""
    clean_name = os.path.basename(filename)
    full_path = os.path.realpath(os.path.join(directory, clean_name))

    if not full_path.startswith(directory):
        raise ValueError("检测到非法文件访问")

    if not os.path.isfile(full_path):
        raise FileNotFoundError(f"文件不存在: {full_path}")

    with open(full_path, "rb") as f:
        return f.read()


def get_master_key(data_dir: str) -> bytes:
    """从 Local State 解析并解密主密钥"""
    raw = read_safe_file(data_dir, "Local State")
    state = json.loads(raw.decode("utf-8"))

    b64_key = state.get("os_crypt", {}).get("encrypted_key")
    if not b64_key:
        raise ValueError("Local State 中缺少 os_crypt.encrypted_key 字段")

    encrypted_key = base64.b64decode(b64_key)
    if not encrypted_key.startswith(b"DPAPI"):
        raise ValueError("encrypted_key 前缀非 DPAPI 标识")

    # 剥离前 5 字节 "DPAPI"，传入 DPAPI 解密
    return _win_dpapi_decrypt(encrypted_key[5:])


def decrypt_token(enc_str: str, master_key: bytes) -> str:
    """解密 enc: 前缀的 AES-256-GCM 令牌密文"""
    if not enc_str.startswith("enc:"):
        return enc_str

    raw = base64.b64decode(enc_str[4:])
    # 格式: v10(3) + IV(12) + Ciphertext + Tag(16)
    if len(raw) < 3 + 12 + 16:
        raise ValueError("密文字节流长度不足")

    if raw[:3] != b"v10":
        raise ValueError("未知的 safeStorage 加密版本标识")

    iv = raw[3:15]
    payload = raw[15:]

    if AESGCM is not None:
        aesgcm = AESGCM(master_key)
        plaintext = aesgcm.decrypt(iv, payload, None)
    else:
        # 若未安装 cryptography 库，提供环境说明
        raise ImportError("请安装 cryptography 库以执行 AES-GCM 解密: pip install cryptography")

    res = plaintext.decode("utf-8")
    if not res.startswith("Bearer "):
        res = "Bearer " + res
    return res


def extract_autoclaw_credentials() -> Dict[str, Any]:
    """一键提取 AutoClaw 桌面端的全部登录凭证信息"""
    data_dir = get_safe_appdata_dir()
    master_key = get_master_key(data_dir)

    auth_raw = read_safe_file(data_dir, "auth.json")
    auth_data = json.loads(auth_raw.decode("utf-8"))

    token_enc = auth_data.get("token", "")
    refresh_enc = auth_data.get("refreshToken", "")

    if not token_enc:
        raise ValueError("auth.json 中未找到 token，请确认 AutoClaw 客户端是否已登录")

    access_token = decrypt_token(token_enc, master_key)
    refresh_token = decrypt_token(refresh_enc, master_key) if refresh_enc else ""

    user_info = auth_data.get("userInfo", {})

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "device_id": auth_data.get("deviceId", ""),
        "user_id": user_info.get("user_id", ""),
        "user_phone": user_info.get("user_phone", ""),
        "user_id_num": user_info.get("id", ""),
    }


if __name__ == "__main__":
    try:
        creds = extract_autoclaw_credentials()
        print("=" * 60)
        print("AutoClaw 桌面端凭据本地自动化解密成功!")
        print("=" * 60)
        print(f"用户 ID   : {creds['user_id']}")
        print(f"用户编号 : {creds['user_id_num']}")
        print(f"手机号码 : {creds['user_phone']}")
        print(f"设备 ID   : {creds['device_id']}")
        # 为保护终端安全，仅展示 Token 前后片段与长度
        tok = creds['access_token']
        print(f"Access Token  (前15位): {tok[:15]}... (总长度: {len(tok)})")
        if creds['refresh_token']:
            rt = creds['refresh_token']
            print(f"Refresh Token (前15位): {rt[:15]}... (总长度: {len(rt)})")
        print("=" * 60)
    except Exception as e:
        print(f"[错误] 解密凭据失败: {e}", file=sys.stderr)
        sys.exit(1)
