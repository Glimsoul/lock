#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AES-256 + HMAC-SHA256 Encryption Tool with HKDF Key Separation
AES-256 + HMAC-SHA256 加密工具，使用 HKDF 进行密钥分离

Version 1.0.0

Usage / 用法:
    lock.py                 Interactive menu / 交互式菜单
    lock.py e "message"     Encrypt a message / 加密消息
    lock.py d "ciphertext"  Decrypt a message / 解密消息
    lock.py --version       Show version and exit / 显示版本并退出
"""

import base64
import os
import sys
import getpass
import re
import subprocess
from typing import Tuple
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

__version__ = "1.0.0"

# ----------------------------------------------------------------------
# Security parameters / 安全参数
# ----------------------------------------------------------------------
SALT_SIZE = 16
KEY_SIZE = 32
IV_SIZE = AES.block_size
HMAC_SIZE = 32
PBKDF2_ITERATIONS = 200000

# ----------------------------------------------------------------------
# Environment detection (cached) / 环境检测（缓存结果）
# ----------------------------------------------------------------------
_TERMUX_CACHE = None

def is_termux() -> bool:
    """Return True if running inside Termux. Result is cached.
    检测是否在 Termux 环境中运行，结果会被缓存。"""
    global _TERMUX_CACHE
    if _TERMUX_CACHE is None:
        _TERMUX_CACHE = 'com.termux' in os.environ.get('PREFIX', '')
    return _TERMUX_CACHE

# ----------------------------------------------------------------------
# Key derivation / 密钥派生
# ----------------------------------------------------------------------
def derive_keys(password: str, salt: bytes) -> Tuple[bytearray, bytearray]:
    """Derive independent AES and HMAC keys from password and salt via HKDF.
    通过 HKDF 从密码和盐值派生出独立的 AES 和 HMAC 密钥。"""
    if not password.strip():
        raise ValueError("Password cannot be empty / 密码不能为空")

    master_key = PBKDF2(
        password.encode('utf-8'),
        salt,
        dkLen=KEY_SIZE,
        count=PBKDF2_ITERATIONS,
        hmac_hash_module=SHA256
    )

    aes_key = bytearray(HKDF(
        master_key, KEY_SIZE, salt=b'',
        context=b'AES-256-CBC-ENCRYPTION', hashmod=SHA256
    ))
    hmac_key = bytearray(HKDF(
        master_key, HMAC_SIZE, salt=b'',
        context=b'HMAC-SHA256-AUTHENTICATION', hashmod=SHA256
    ))
    return aes_key, hmac_key

# ----------------------------------------------------------------------
# Secure memory wipe / 安全内存擦除
# ----------------------------------------------------------------------
def _clear_bytes(data: bytearray) -> None:
    """Overwrite bytearray with zeros to scrub sensitive data.
    用零覆盖字节数组，清除敏感数据。"""
    data[:] = b'\x00' * len(data)

# ----------------------------------------------------------------------
# Encryption / 加密
# ----------------------------------------------------------------------
def encrypt(plaintext: str, password: str) -> str:
    """Encrypt plaintext with password, return Base64 ciphertext.
    用密码加密明文，返回 Base64 密文。"""
    salt = get_random_bytes(SALT_SIZE)
    aes_key, hmac_key = derive_keys(password, salt)
    iv = get_random_bytes(IV_SIZE)

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))

    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(salt + iv + ciphertext)
    hmac_value = h.digest()

    combined = salt + iv + ciphertext + hmac_value
    return base64.b64encode(combined).decode('ascii')
# ----------------------------------------------------------------------
# Decryption / 解密
# ----------------------------------------------------------------------
def decrypt(ciphertext_b64: str, password: str) -> str:
    """Decrypt Base64 ciphertext with password, return original plaintext.
    用密码解密 Base64 密文，返回原始明文。"""
    cleaned = re.sub(r'[\s\0]+', '', ciphertext_b64)
    try:
        data = base64.b64decode(cleaned)
    except Exception:
        raise ValueError('Decryption failed / 解密失败') from None

    if len(data) < SALT_SIZE + IV_SIZE + HMAC_SIZE:
        raise ValueError('Decryption failed / 解密失败')

    salt = data[:SALT_SIZE]
    iv = data[SALT_SIZE:SALT_SIZE+IV_SIZE]
    ciphertext = data[SALT_SIZE+IV_SIZE:-HMAC_SIZE]
    received_hmac = data[-HMAC_SIZE:]

    aes_key = hmac_key = None
    try:
        aes_key, hmac_key = derive_keys(password, salt)

        h = HMAC.new(hmac_key, digestmod=SHA256)
        h.update(salt + iv + ciphertext)
        h.verify(received_hmac)

        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode('utf-8')

    except (ValueError, HMAC.MACError):
        raise ValueError('Decryption failed / 解密失败') from None
    finally:
        if aes_key is not None:
            _clear_bytes(aes_key)
        if hmac_key is not None:
            _clear_bytes(hmac_key)

# ----------------------------------------------------------------------
# Password input / 密码输入
# ----------------------------------------------------------------------
def input_password(confirm: bool = False) -> str:
    """Securely prompt for password, optionally with confirmation.
    安全提示输入密码，可选二次确认。"""
    while True:
        pwd = getpass.getpass('Password: ')
        if not pwd.strip():
            print('Password cannot be empty / 密码不能为空')
            continue
        if confirm:
            if pwd != getpass.getpass('Confirm password: '):
                print('Passwords do not match / 密码不匹配')
                continue
        return pwd

# ----------------------------------------------------------------------
# Clipboard support (Termux only) / 剪贴板支持
# ----------------------------------------------------------------------
def copy_to_clipboard(text: str) -> bool:
    """Copy text to clipboard if in Termux with termux-api installed.
    若在 Termux 中且安装了 termux-api，则将文本复制到剪贴板。"""
    if not is_termux():
        return False
    try:
        proc = subprocess.Popen(
            ['termux-clipboard-set'],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        proc.communicate(input=text.encode('utf-8'), timeout=2)
        return proc.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

# ----------------------------------------------------------------------
# Interactive menu / 交互式菜单
# ----------------------------------------------------------------------
def interactive_menu() -> None:
    """Display interactive menu for encryption/decryption.
    显示加密/解密的交互式菜单。"""
    while True:
        os.system('clear 2>/dev/null || cls 2>/dev/null || echo -e "\033c"')
        print('\nAES-256 + HMAC (HKDF)')
        print('[1] Encrypt / 加密')
        print('[2] Decrypt / 解密')
        print('[3] Exit / 退出')
        choice = input('Select (1-3) / 请选择 (1-3): ').strip()

        if choice == '1':
            plain = input('Text to encrypt / 要加密的文本: ').strip()
            if not plain:
                print('Text cannot be empty / 文本不能为空')
                input('Press Enter to continue... / 按回车继续...')
                continue
            pwd = input_password(confirm=True)
            try:
                result = encrypt(plain, pwd)
                print('\nEncrypted (copy the line below) / 加密结果（复制下面这行）:')
                print(result)
                if copy_to_clipboard(result):
                    print('(Copied to clipboard / 已复制到剪贴板)')
            except Exception as e:
                print(f'Encryption failed / 加密失败: {e}')
            input('\nPress Enter to continue... / 按回车继续...')

        elif choice == '2':
            print('\nPaste Base64 ciphertext. / 请粘贴 Base64 密文。')
            print('In Termux: long press screen -> Paste -> press Enter')
            print('在 Termux 中：长按屏幕 -> 粘贴 -> 按回车')
            cipher = input('Ciphertext / 密文: ').strip()
            if not cipher:
                print('Ciphertext cannot be empty / 密文不能为空')
                input('Press Enter to continue... / 按回车继续...')
                continue
            pwd = input_password()
            try:
                plain = decrypt(cipher, pwd)
                print('\nDecrypted / 解密结果:')
                print(plain)
            except ValueError as e:
                print(f'Decryption failed / 解密失败: {e}')
            input('\nPress Enter to continue... / 按回车继续...')

        elif choice == '3':
            print('Goodbye. / 再见。')
            sys.exit(0)
        else:
            print('Invalid choice / 无效选择')
            input('Press Enter to continue... / 按回车继续...')

# ----------------------------------------------------------------------
# Command-line mode / 命令行模式
# ----------------------------------------------------------------------
def command_mode() -> None:
    """Handle command-line encryption, decryption, and version query.
    处理命令行加密、解密及版本查询。"""
    if len(sys.argv) < 2:
        print('Usage / 用法:')
        print('  lock.py e "message"')
        print('  lock.py d "ciphertext"')
        print('  lock.py --version')
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == '--version':
        print(f'lock.py version {__version__}')
        sys.exit(0)

    if cmd not in ('e', 'd') or len(sys.argv) < 3:
        print('Usage / 用法:')
        print('  lock.py e "message"')
        print('  lock.py d "ciphertext"')
        print('  lock.py --version')
        sys.exit(1)

    content = ' '.join(sys.argv[2:])
    pwd = input_password(confirm=(cmd == 'e'))

    try:
        if cmd == 'e':
            print(encrypt(content, pwd))
        else:
            print(decrypt(content, pwd))
    except ValueError as e:
        print(f'Error / 错误: {e}')
        sys.exit(1)

# ----------------------------------------------------------------------
# Main / 主函数
# ----------------------------------------------------------------------
def main() -> None:
    """Main entry point. / 主入口点。"""
    if is_termux():
        clip_path = '/data/data/com.termux/files/usr/bin/termux-clipboard-set'
        if not os.path.exists(clip_path):
            print('Note: Install termux-api for clipboard support: pkg install termux-api')
            print('提示：安装 termux-api 以支持剪贴板：pkg install termux-api')

    if len(sys.argv) == 1:
        try:
            interactive_menu()
        except KeyboardInterrupt:
            print('\nExited / 已退出')
    else:
        command_mode()

if __name__ == '__main__':
    main()
