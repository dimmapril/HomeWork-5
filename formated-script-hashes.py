import os, base64, hashlib

PASSWORDS = [
    "qwertyuiop",
    "sofPed-westag-jejzo1",
    "f3Fg#Puu$EA1mfMx2",
    "TIMCfJDkKBRm9/zwcFbHhE6zaMcSxR7nke1mJKcVqXpvCzg69d7Mf2quanMoAfmPJXyqT4gyGpLoL1lTHoqmwVmaUwrpOPRecB8GAU17eUJJHiksv3qrqcVxhgpMkX/UlKaLdFSwFIr7cVoJmBqQ/buWzxJNCIo7qbtIi3fSi62NwMHh",
]

N_LOG2 = 14          # підніматься на проді для калібрування
N = 1 << N_LOG2
R = 8
P = 1
DKLEN = 32          # 256 біт довжина ключа

def scrypt_phc(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode("utf-8"),
                        salt=salt, n=N, r=R, p=P, dklen=DKLEN)
    salt_b64 = base64.b64encode(salt).decode("ascii")
    dk_b64 = base64.b64encode(dk).decode("ascii")
    return f"$scrypt$ln={N_LOG2},r={R},p={P}${salt_b64}${dk_b64}"

if __name__ == "__main__":
    for pw in PASSWORDS:
        print(scrypt_phc(pw))
