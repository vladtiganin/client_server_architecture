from __future__ import annotations

import math
import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class RSAKey:
    first: int
    second: int


def _bytes_to_int(data: bytes) -> int:
    if not data:
        return 0
    return int.from_bytes(data, byteorder="big")


def _int_to_bytes(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    return value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")


def _is_probable_prime(number: int, rounds: int = 40) -> bool:
    if number < 2:
        return False
    for prime in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if number == prime:
            return True
        if number % prime == 0:
            return False

    d = number - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(rounds):
        a = secrets.randbelow(number - 3) + 2
        x = pow(a, d, number)
        if x in (1, number - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, number)
            if x == number - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


class RSA:
    def __init__(self) -> None:
        self._public_key: RSAKey | None = None
        self._private_key: RSAKey | None = None

    @property
    def public_key(self) -> RSAKey:
        if self._public_key is None:
            raise RuntimeError("Keys not generated")
        return self._public_key

    @property
    def private_key(self) -> RSAKey:
        if self._private_key is None:
            raise RuntimeError("Keys not generated")
        return self._private_key

    def generate_keys(self, key_size: int = 1024) -> None:
        if key_size < 512:
            raise ValueError("key_size must be at least 512 bits")

        e = 65537
        half_bits = key_size // 2
        while True:
            p = _generate_prime(half_bits)
            q = _generate_prime(key_size - half_bits)
            if p == q:
                continue

            n = p * q
            phi = (p - 1) * (q - 1)
            if math.gcd(e, phi) == 1:
                break

        d = pow(e, -1, phi)
        self._public_key = RSAKey(e, n)
        self._private_key = RSAKey(d, n)

    def encrypt(self, data: int) -> int:
        return self.encrypt_with_key(data, self.public_key)

    def decrypt(self, encrypted_key: int) -> int:
        return self.decrypt_with_key(encrypted_key, self.private_key)

    def encrypt_bytes(self, data: bytes) -> bytes:
        return self.encrypt_bytes_with_key(data, self.public_key)

    def decrypt_bytes(self, data: bytes) -> bytes:
        return self.decrypt_bytes_with_key(data, self.private_key)

    @staticmethod
    def encrypt_with_key(data: int, key: RSAKey) -> int:
        if data >= key.second:
            raise ValueError("Data too large for RSA modulus")
        return pow(data, key.first, key.second)

    @staticmethod
    def decrypt_with_key(encrypted_data: int, key: RSAKey) -> int:
        return pow(encrypted_data, key.first, key.second)

    @staticmethod
    def encrypt_bytes_with_key(data: bytes, key: RSAKey) -> bytes:
        data_int = _bytes_to_int(data)
        if data_int >= key.second:
            raise ValueError("Data too large for RSA modulus")
        encrypted = pow(data_int, key.first, key.second)
        return _int_to_bytes(encrypted)

    @staticmethod
    def decrypt_bytes_with_key(encrypted_data: bytes, key: RSAKey, original_size: int = 0) -> bytes:
        encrypted_int = _bytes_to_int(encrypted_data)
        decrypted = _int_to_bytes(pow(encrypted_int, key.first, key.second))
        if original_size > 0 and len(decrypted) < original_size:
            decrypted = (b"\x00" * (original_size - len(decrypted))) + decrypted
        return decrypted
