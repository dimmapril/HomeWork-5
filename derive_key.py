#!/usr/bin/env python3
import os, json, base64, hashlib, secrets, pathlib
from typing import Tuple

META_PATH = pathlib.Path("users_kdf.json")

DEFAULT_PARAMS = {"ln": 15, "r": 8, "p": 1, "dklen": 16}

def _load_meta():
    if META_PATH.exists():
        with open(META_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

def _save_meta(data):
    with open(META_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def _get_or_create_user_meta(username: str):
    data = _load_meta()
    for rec in data:
        if rec.get("username") == username:
            return rec, data
    salt = secrets.token_bytes(16)
    rec = {
        "username": username,
        "salt": base64.b64encode(salt).decode("ascii"),
        "params": DEFAULT_PARAMS.copy()
    }
    data.append(rec); _save_meta(data)
    return rec, data

def derive_key(username: str, password: str) -> bytes:
    rec, _ = _get_or_create_user_meta(username)
    salt = base64.b64decode(rec["salt"])
    ln   = int(rec["params"]["ln"]); N = 1 << ln
    r    = int(rec["params"]["r"]);  p = int(rec["params"]["p"])
    dk   = int(rec["params"]["dklen"])
    key = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=N, r=r, p=p, dklen=dk)
    return key

def derive_key_hex(username: str, password: str) -> str:
    return derive_key(username, password).hex()

if __name__ == "__main__":
    import argparse, pathlib as _p
    ap = argparse.ArgumentParser(description="Derive AES-128 key via scrypt; per-user salt stored in JSON.")
    ap.add_argument("username"); ap.add_argument("password")
    ap.add_argument("--meta", default=str(META_PATH), help="Path to users_kdf.json")
    args = ap.parse_args()
    global META_PATH; META_PATH = _p.Path(args.meta)
    print(derive_key_hex(args.username, args.password))
