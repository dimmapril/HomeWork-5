#!/usr/bin/env python3
from hashlib import sha256
import hmac, sys

def fix_hex(s: str) -> bytes:
    s = s.strip().lower()
    if len(s) % 2 == 1:
        s = "0" + s
    return bytes.fromhex(s)

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, sha256).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""; t = b""; c = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([c]), sha256).digest()
        out += t; c += 1
    return out[:length]

def gen_mac_hex(master_key_hex: str, iv_hex: str, cipher_hex: str) -> str:
    ikm = fix_hex(master_key_hex)
    iv  = fix_hex(iv_hex)
    c   = fix_hex(cipher_hex)
    prk   = hkdf_extract(iv, ikm)
    k_mac = hkdf_expand(prk, b"mac", 32)
    tag = hmac.new(k_mac, iv + c, sha256).digest()
    return tag.hex()

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: generate_mac.py <master_key_hex> <iv_hex> <cipher_hex>")
        sys.exit(1)
    print(gen_mac_hex(sys.argv[1], sys.argv[2], sys.argv[3]))
