#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import os
import sys
import getpass
import re
import subprocess
import shutil
import time
from typing import Optional, Tuple

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

__version__ = "1.1.0"

SALT_SIZE = 16
AES_KEY_SIZE = 32
HMAC_KEY_SIZE = 32
MASTER_KEY_SIZE = AES_KEY_SIZE + HMAC_KEY_SIZE
IV_SIZE = AES.block_size
HMAC_TAG_SIZE = 32
PBKDF2_ITERATIONS = 200000
B64_LINE_WIDTH = 76

_PLATFORM_NAME: Optional[str] = None


def _detect_platform() -> str:
    global _PLATFORM_NAME
    if _PLATFORM_NAME is not None:
        return _PLATFORM_NAME

    if 'com.termux' in os.environ.get('PREFIX', '') or 'TERMUX_VERSION' in os.environ:
        _PLATFORM_NAME = 'termux'
    elif sys.platform == 'darwin':
        _PLATFORM_NAME = 'macos'
    elif sys.platform.startswith('linux') or sys.platform.startswith('freebsd'):
        _PLATFORM_NAME = 'linux'
    elif sys.platform == 'win32' or sys.platform == 'cygwin':
        _PLATFORM_NAME = 'windows'
    else:
        _PLATFORM_NAME = 'unknown'
    return _PLATFORM_NAME


def _clear_bytes(data: bytearray) -> None:
    if data:
        data[:] = b'\x00' * len(data)


def derive_keys(password: str, salt: bytes) -> Tuple[bytearray, bytearray]:
    if not password.strip():
        raise ValueError("Password cannot be empty")

    master_key_bytes = PBKDF2(
        password.encode('utf-8'),
        salt,
        dkLen=MASTER_KEY_SIZE,
        count=PBKDF2_ITERATIONS,
        hmac_hash_module=SHA256
    )
    master_key = bytearray(master_key_bytes)

    try:
        aes_key_bytes = HKDF(
            master_key, AES_KEY_SIZE, salt=b'',
            context=b'AES-256-CBC-ENCRYPTION', hashmod=SHA256
        )
        hmac_key_bytes = HKDF(
            master_key, HMAC_KEY_SIZE, salt=b'',
            context=b'HMAC-SHA256-AUTHENTICATION', hashmod=SHA256
        )
        aes_key = bytearray(aes_key_bytes)
        hmac_key = bytearray(hmac_key_bytes)
        return aes_key, hmac_key
    finally:
        _clear_bytes(master_key)


def _b64_encode(data: bytes) -> str:
    raw = base64.b64encode(data).decode('ascii')
    lines = [raw[i:i + B64_LINE_WIDTH] for i in range(0, len(raw), B64_LINE_WIDTH)]
    return '\n'.join(lines)


def _b64_decode(text: str) -> bytes:
    cleaned = re.sub(r'[^A-Za-z0-9+/=]', '', text)
    return base64.b64decode(cleaned)


def encrypt(plaintext: str, password: str) -> str:
    salt = get_random_bytes(SALT_SIZE)
    aes_key, hmac_key = derive_keys(password, salt)
    iv = get_random_bytes(IV_SIZE)

    try:
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))

        h = HMAC.new(hmac_key, digestmod=SHA256)
        h.update(salt + iv + ciphertext)
        hmac_value = h.digest()

        combined = salt + iv + ciphertext + hmac_value
        return _b64_encode(combined)
    finally:
        _clear_bytes(aes_key)
        _clear_bytes(hmac_key)


def decrypt(ciphertext_b64: str, password: str, verbose: bool = False) -> str:
    cleaned = re.sub(r'[^A-Za-z0-9+/=]', '', ciphertext_b64)
    if verbose and cleaned != ciphertext_b64:
        sys.stderr.write("Note: Non-Base64 characters removed.\n")

    try:
        data = base64.b64decode(cleaned)
    except Exception:
        raise ValueError("Invalid Base64")

    if len(data) < SALT_SIZE + IV_SIZE + HMAC_TAG_SIZE:
        raise ValueError("Ciphertext too short")

    salt = data[:SALT_SIZE]
    iv = data[SALT_SIZE:SALT_SIZE + IV_SIZE]
    ciphertext = data[SALT_SIZE + IV_SIZE:-HMAC_TAG_SIZE]
    received_hmac = data[-HMAC_TAG_SIZE:]

    aes_key = hmac_key = None
    try:
        aes_key, hmac_key = derive_keys(password, salt)

        h = HMAC.new(hmac_key, digestmod=SHA256)
        h.update(salt + iv + ciphertext)
        h.verify(received_hmac)

        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode('utf-8')
    except ValueError:
        raise
    finally:
        if aes_key:
            _clear_bytes(aes_key)
        if hmac_key:
            _clear_bytes(hmac_key)
            def copy_to_clipboard(text: str) -> bool:
    platform = _detect_platform()

    if platform == 'termux':
        clip_cmd = shutil.which('termux-clipboard-set')
        if not clip_cmd:
            return False
        return _run_clip_cmd([clip_cmd], text)

    if platform == 'macos':
        return _run_clip_cmd(['pbcopy'], text)

    if platform == 'linux':
        for cmd_name in ('xclip', 'xsel', 'wl-copy'):
            clip_cmd = shutil.which(cmd_name)
            if not clip_cmd:
                continue
            if cmd_name == 'xclip':
                return _run_clip_cmd([clip_cmd, '-selection', 'clipboard'], text)
            elif cmd_name == 'xsel':
                return _run_clip_cmd([clip_cmd, '--clipboard', '--input'], text)
            else:  # wl-copy
                return _run_clip_cmd([clip_cmd], text)
        return False

    if platform == 'windows':
        try:
            import ctypes
            CF_UNICODETEXT = 13
            GMEM_MOVEABLE = 0x0002

            kernel32 = ctypes.windll.kernel32
            user32 = ctypes.windll.user32

            encoded = text.encode('utf-16-le') + b'\x00\x00'
            buf_size = len(encoded)
            h_mem = kernel32.GlobalAlloc(GMEM_MOVEABLE, buf_size)
            if not h_mem:
                return False
            ptr = kernel32.GlobalLock(h_mem)
            if not ptr:
                kernel32.GlobalFree(h_mem)
                return False
            ctypes.memmove(ptr, encoded, buf_size)
            kernel32.GlobalUnlock(h_mem)

            if not user32.OpenClipboard(None):
                kernel32.GlobalFree(h_mem)
                return False
            user32.EmptyClipboard()
            result = user32.SetClipboardData(CF_UNICODETEXT, h_mem)
            user32.CloseClipboard()
            return result is not None
        except Exception:
            return False

    return False


def _run_clip_cmd(cmd: list, text: str) -> bool:
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        try:
            proc.communicate(input=text.encode('utf-8'), timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            return False
        return proc.returncode == 0
    except (FileNotFoundError, OSError):
        return False


def _read_from_file(filepath: str) -> str:
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        print(f"File not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Permission denied: {filepath}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Read error: {e}", file=sys.stderr)
        sys.exit(1)


def _write_to_file(filepath: str, content: str) -> None:
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
    except PermissionError:
        print(f"Permission denied: {filepath}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Write error: {e}", file=sys.stderr)
        sys.exit(1)


def input_password(confirm: bool = False) -> str:
    while True:
        pwd = getpass.getpass('Password: ')
        if not pwd.strip():
            print('Password cannot be empty')
            continue
        if confirm:
            if pwd != getpass.getpass('Confirm password: '):
                print('Passwords do not match')
                continue
        return pwd


def clear_screen() -> None:
    os.system('cls' if os.name == 'nt' else 'clear')
    def _interactive_encrypt_text() -> None:
    plain = input('\nText to encrypt: ').strip()
    if not plain:
        print('Text cannot be empty')
        input('Press Enter to continue...')
        return
    pwd = input_password(confirm=True)
    try:
        result = encrypt(plain, pwd)
        print('\nEncrypted:')
        print(result)
        if copy_to_clipboard(result):
            print('\n(Copied to clipboard)')
    except ValueError:
        print('Encryption failed')
    except Exception as e:
        print(f'Error: {e}')
    input('\nPress Enter to continue...')


def _interactive_decrypt_text() -> None:
    print('\nPaste Base64 ciphertext:')
    cipher = input('Ciphertext: ').strip()
    if not cipher:
        print('Ciphertext cannot be empty')
        input('Press Enter to continue...')
        return
    pwd = input_password()
    try:
        plain = decrypt(cipher, pwd, verbose=True)
        print('\nDecrypted:')
        print(plain)
        if copy_to_clipboard(plain):
            print('\n(Copied to clipboard)')
    except ValueError:
        print('Decryption failed — wrong password or corrupted data')
    except Exception as e:
        print(f'Error: {e}')
    input('\nPress Enter to continue...')


def _interactive_encrypt_file() -> None:
    src = input('\nSource file path: ').strip()
    if not src:
        print('Path cannot be empty')
        input('Press Enter to continue...')
        return
    dst = input('Output file (Enter for stdout): ').strip()
    content = _read_from_file(src)
    pwd = input_password(confirm=True)
    try:
        result = encrypt(content, pwd)
        if dst:
            _write_to_file(dst, result)
            print(f'Saved to: {dst}')
        else:
            print('\nEncrypted:')
            print(result)
    except Exception as e:
        print(f'Encryption failed: {e}')
    input('\nPress Enter to continue...')


def _interactive_decrypt_file() -> None:
    src = input('\nSource file path: ').strip()
    if not src:
        print('Path cannot be empty')
        input('Press Enter to continue...')
        return
    dst = input('Output file (Enter for stdout): ').strip()
    content = _read_from_file(src)
    pwd = input_password()
    try:
        result = decrypt(content, pwd, verbose=True)
        if dst:
            _write_to_file(dst, result)
            print(f'Saved to: {dst}')
        else:
            print('\nDecrypted:')
            print(result)
    except ValueError:
        print('Decryption failed — wrong password or corrupted data')
    except Exception as e:
        print(f'Decryption failed: {e}')
    input('\nPress Enter to continue...')


def interactive_menu() -> None:
    while True:
        clear_screen()
        time.sleep(0.05)
        print('\n  AES-256 + HMAC (HKDF)  v1.1.0')
        print('─' * 40)
        print('  [1] Encrypt text')
        print('  [2] Decrypt text')
        print('  [3] Encrypt file')
        print('  [4] Decrypt file')
        print('  [5] Exit')
        print('─' * 40)
        choice = input('  Select (1-5): ').strip()

        if choice == '1':
            _interactive_encrypt_text()
        elif choice == '2':
            _interactive_decrypt_text()
        elif choice == '3':
            _interactive_encrypt_file()
        elif choice == '4':
            _interactive_decrypt_file()
        elif choice == '5':
            print('Goodbye.')
            sys.exit(0)
        else:
            print('Invalid choice')
            input('Press Enter to continue...')
def _extract_flag(flag: str, argv: list) -> Optional[str]:
    for i, arg in enumerate(argv):
        if arg == flag and i + 1 < len(argv):
            return argv[i + 1]
    return None


def _print_usage() -> None:
    print("""Usage:
  lock.py e "text" [-o file]       Encrypt text
  lock.py d "ciphertext" [-o file] Decrypt text
  lock.py ef <file> [-o file]      Encrypt file
  lock.py df <file> [-o file]      Decrypt file
  lock.py --version                Show version
  lock.py                          Interactive mode
""")


def command_mode() -> None:
    if len(sys.argv) < 2:
        _print_usage()
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd in ('-h', '--help'):
        _print_usage()
        sys.exit(0)

    if cmd == '--version':
        print(f'lock.py {__version__}')
        sys.exit(0)

    if cmd == 'e':
        if len(sys.argv) < 3:
            print('Missing text', file=sys.stderr)
            sys.exit(1)
        text = ' '.join(sys.argv[2:])
        output = _extract_flag('-o', sys.argv)
        pwd = input_password(confirm=True)
        try:
            result = encrypt(text, pwd)
            if output:
                _write_to_file(output, result)
            else:
                print(result)
        except Exception as e:
            print(f'Error: {e}', file=sys.stderr)
            sys.exit(1)

    elif cmd == 'd':
        if len(sys.argv) < 3:
            print('Missing ciphertext', file=sys.stderr)
            sys.exit(1)
        if len(sys.argv) > 3 and not sys.argv[2].startswith('-'):
            print('Warning: multiple arguments — did you forget quotes?', file=sys.stderr)
        cipher = sys.argv[2]
        output = _extract_flag('-o', sys.argv)
        pwd = input_password()
        try:
            result = decrypt(cipher, pwd, verbose=False)
            if output:
                _write_to_file(output, result)
            else:
                print(result)
        except ValueError:
            print('Decryption failed — wrong password or corrupted data', file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f'Error: {e}', file=sys.stderr)
            sys.exit(1)

    elif cmd == 'ef':
        if len(sys.argv) < 3:
            print('Missing input file', file=sys.stderr)
            sys.exit(1)
        input_file = sys.argv[2]
        output = _extract_flag('-o', sys.argv) or (input_file + '.enc')
        content = _read_from_file(input_file)
        pwd = input_password(confirm=True)
        try:
            result = encrypt(content, pwd)
            _write_to_file(output, result)
            print(f'Saved to: {output}')
        except Exception as e:
            print(f'Error: {e}', file=sys.stderr)
            sys.exit(1)

    elif cmd == 'df':
        if len(sys.argv) < 3:
            print('Missing input file', file=sys.stderr)
            sys.exit(1)
        input_file = sys.argv[2]
        output = _extract_flag('-o', sys.argv)
        if not output:
            output = input_file.removesuffix('.enc') if input_file.endswith('.enc') else (input_file + '.dec')
        content = _read_from_file(input_file)
        pwd = input_password()
        try:
            result = decrypt(content, pwd, verbose=False)
            _write_to_file(output, result)
            print(f'Saved to: {output}')
        except ValueError:
            print('Decryption failed — wrong password or corrupted data', file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f'Error: {e}', file=sys.stderr)
            sys.exit(1)

    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        _print_usage()
        sys.exit(1)


def main() -> None:
    platform = _detect_platform()
    if platform == 'termux' and shutil.which('termux-clipboard-set') is None:
        print('Tip: pkg install termux-api for clipboard support')

    if len(sys.argv) == 1:
        try:
            interactive_menu()
        except KeyboardInterrupt:
            print('\nExited')
    else:
        command_mode()


if __name__ == '__main__':
    main()
