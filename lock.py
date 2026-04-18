#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AES-256 + HMAC-SHA256 encryption tool with HKDF key separation.
AES-256 + HMAC-SHA256 加密工具，使用 HKDF 进行密钥分离。

Usage / 用法:
    lock.py                 Interactive menu / 交互式菜单
    lock.py e "message"     Encrypt / 加密
    lock.py d "ciphertext"  Decrypt / 解密
"""

import base64
import os
import sys
import getpass
import re
import subprocess
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

# ----------------------------------------------------------------------
# Security parameters / 安全参数
# ----------------------------------------------------------------------
SALT_SIZE = 16                     # Salt size in bytes / 盐值长度（字节）
KEY_SIZE = 32                      # AES-256 key size / AES-256 密钥长度
IV_SIZE = AES.block_size           # AES block size (16 bytes) / AES 块大小（16 字节）
HMAC_SIZE = 32                     # HMAC-SHA256 output size / HMAC-SHA256 输出长度
PBKDF2_ITERATIONS = 200000         # PBKDF2 iteration count / PBKDF2 迭代次数

# ----------------------------------------------------------------------
# Environment detection / 环境检测
# ----------------------------------------------------------------------
def is_termux():
    """Return True if running inside Termux environment.
    如果在 Termux 环境中运行则返回 True。"""
    return 'com.termux' in os.environ.get('PREFIX', '')

# ----------------------------------------------------------------------
# Key derivation (PBKDF2 + HKDF) / 密钥派生（PBKDF2 + HKDF）
# ----------------------------------------------------------------------
def derive_keys(password: str, salt: bytes):
    """Derive AES and HMAC keys from password and salt using HKDF.
    使用 HKDF 从密码和盐值派生出 AES 密钥和 HMAC 密钥。"""
    if not password.strip():
        raise ValueError("Password cannot be empty / 密码不能为空")

    # Master key from PBKDF2 / 通过 PBKDF2 生成主密钥
    master_key = PBKDF2(
        password.encode('utf-8'),
        salt,
        dkLen=32,
        count=PBKDF2_ITERATIONS,
        hmac_hash_module=SHA256
    )

    # Separate keys via HKDF with different context strings
    # 通过 HKDF 使用不同的上下文字符串分离密钥
    aes_key = bytearray(HKDF(
        master_key,
        KEY_SIZE,
        salt=b'',
        context=b'AES-256-CBC-ENCRYPTION',
        hashmod=SHA256
    ))
    hmac_key = bytearray(HKDF(
        master_key,
        HMAC_SIZE,
        salt=b'',
        context=b'HMAC-SHA256-AUTHENTICATION',
        hashmod=SHA256
    ))
    return aes_key, hmac_key

# ----------------------------------------------------------------------
# Secure memory erasure / 安全内存擦除
# ----------------------------------------------------------------------
def _clear_bytes(data: bytearray) -> None:
    """Overwrite bytearray with zeros to remove sensitive data from memory.
    用零覆盖字节数组，从内存中清除敏感数据。"""
    for i in range(len(data)):
        data[i] = 0# ----------------------------------------------------------------------
# Encryption / 加密
# ----------------------------------------------------------------------
def encrypt(plaintext: str, password: str) -> str:
    """Encrypt plaintext with password, return Base64 encoded ciphertext.
    使用密码加密明文，返回 Base64 编码的密文。"""
    salt = get_random_bytes(SALT_SIZE)
    aes_key, hmac_key = derive_keys(password, salt)
    iv = get_random_bytes(IV_SIZE)

    # AES-CBC encryption / AES-CBC 加密
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded)

    # HMAC over salt + IV + ciphertext / 对 salt + IV + 密文计算 HMAC
    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(salt + iv + ciphertext)
    hmac_value = h.digest()

    # Combine all parts and encode as Base64
    # 将所有部分组合并进行 Base64 编码
    combined = salt + iv + ciphertext + hmac_value
    return base64.b64encode(combined).decode('ascii')

# ----------------------------------------------------------------------
# Decryption / 解密
# ----------------------------------------------------------------------
def decrypt(ciphertext_b64: str, password: str) -> str:
    """Decrypt Base64 ciphertext with password, return original plaintext.
    使用密码解密 Base64 密文，返回原始明文。"""
    # Remove any whitespace or null characters / 移除所有空白字符和空字符
    cleaned = re.sub(r'[\s\0]+', '', ciphertext_b64)
    try:
        data = base64.b64decode(cleaned)
    except Exception:
        raise ValueError('Decryption failed / 解密失败')

    if len(data) < SALT_SIZE + IV_SIZE + HMAC_SIZE:
        raise ValueError('Decryption failed / 解密失败')

    # Split components / 拆分各组件
    salt = data[:SALT_SIZE]
    iv = data[SALT_SIZE:SALT_SIZE+IV_SIZE]
    hmac_start = len(data) - HMAC_SIZE
    ciphertext = data[SALT_SIZE+IV_SIZE:hmac_start]
    received_hmac = data[hmac_start:]

    aes_key = hmac_key = None
    try:
        aes_key, hmac_key = derive_keys(password, salt)

        # Verify HMAC before decryption / 解密前先验证 HMAC
        h = HMAC.new(hmac_key, digestmod=SHA256)
        h.update(salt + iv + ciphertext)
        h.verify(received_hmac)

        # AES-CBC decryption / AES-CBC 解密
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        plaintext = unpad(decrypted_padded, AES.block_size)
        return plaintext.decode('utf-8')

    except (ValueError, HMAC.MACError):
        raise ValueError('Decryption failed / 解密失败') from None
    finally:
        # Securely erase keys from memory / 从内存中安全擦除密钥
        if aes_key is not None:
            _clear_bytes(aes_key)
        if hmac_key is not None:
            _clear_bytes(hmac_key)# ----------------------------------------------------------------------
# Password input / 密码输入
# ----------------------------------------------------------------------
def input_password(confirm: bool = False) -> str:
    """Prompt for password securely, optionally confirm.
    安全地提示输入密码，可选确认。"""
    while True:
        pwd = getpass.getpass('Password: ')
        if not pwd.strip():
            print('Password cannot be empty / 密码不能为空')
            continue
        if confirm:
            pwd2 = getpass.getpass('Confirm password: ')
            if pwd != pwd2:
                print('Passwords do not match / 密码不匹配')
                continue
        return pwd

# ----------------------------------------------------------------------
# Clipboard support (Termux only) / 剪贴板支持（仅 Termux）
# ----------------------------------------------------------------------
def copy_to_clipboard(text: str) -> bool:
    """Copy text to clipboard if running in Termux with termux-api installed.
    如果在 Termux 中且安装了 termux-api，则将文本复制到剪贴板。"""
    if not is_termux():
        return False
    try:
        proc = subprocess.Popen(
            ['termux-clipboard-set'],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        proc.communicate(input=text.encode('utf-8'))
        return proc.returncode == 0
    except FileNotFoundError:
        return False

# ----------------------------------------------------------------------
# Interactive menu (with screen clear and pause)
# 交互式菜单（带清屏和暂停）
# ----------------------------------------------------------------------
def interactive_menu():
    """Display interactive menu for encryption/decryption.
    显示加密/解密的交互式菜单。"""
    while True:
        # Clear screen (Termux compatible) / 清屏（兼容 Termux）
        os.system('clear 2>/dev/null || cls 2>/dev/null || echo -e "\033c"')
        print()
        print('AES-256 + HMAC (HKDF)')
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
                print()
                print('Encrypted (copy the line below) / 加密结果（复制下面这行）:')
                print(result)
                if copy_to_clipboard(result):
                    print('(Copied to clipboard / 已复制到剪贴板)')
            except Exception as e:
                print(f'Encryption failed / 加密失败: {e}')
            input('\nPress Enter to continue... / 按回车继续...')

        elif choice == '2':
            print()
            print('Paste Base64 ciphertext. / 请粘贴 Base64 密文。')
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
                print()
                print('Decrypted / 解密结果:')
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
def command_mode():
    """Handle command-line encryption/decryption.
    处理命令行加密/解密。"""
    if len(sys.argv) < 3 or sys.argv[1] not in ('e', 'd'):
        print('Usage / 用法:')
        print('  lock.py e "message"')
        print('  lock.py d "ciphertext"')
        sys.exit(1)

    mode = sys.argv[1]
    content = ' '.join(sys.argv[2:])
    pwd = input_password(confirm=(mode == 'e'))

    try:
        if mode == 'e':
            print(encrypt(content, pwd))
        else:
            print(decrypt(content, pwd))
    except ValueError as e:
        print(f'Error / 错误: {e}')
        sys.exit(1)

# ----------------------------------------------------------------------
# Main / 主函数
# ----------------------------------------------------------------------
def main():
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
