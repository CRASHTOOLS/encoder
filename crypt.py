"""модуль шифрования"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii


def generate_key() -> bytes:
    """
    генерирует случайный ключ.
    """
    return get_random_bytes(32)


def key_from_hex(hex_key: str) -> bytes:
    """
    преобразует hex-строку в bytes ключ.
    """
    if len(hex_key) != 64:
        raise ValueError("Ключ должен быть 64 hex символа")
    try:
        return binascii.unhexlify(hex_key)
    except binascii.Error as error:
        raise ValueError("Неверный формат ключа") from error


def encrypt(data: bytes, key: bytes) -> bytes:
    """
    шифрует данные алгоритмом AES-256-CBC.
    """
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.iv + cipher.encrypt(pad(data, AES.block_size))


def decrypt(data: bytes, key: bytes) -> bytes:
    """
    расшифровывает данные алгоритмом AES-256-CBC.
    """
    initialization_vector = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=initialization_vector)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)
