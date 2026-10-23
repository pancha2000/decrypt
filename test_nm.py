#!/usr/bin/env python3
"""NetMod .nm comprehensive decryptor diagnostic."""
import sys, base64, re
from collections import Counter
from Crypto.Cipher import AES, ChaCha20
from Crypto.Util.Padding import unpad

KEYS = [
    ("K1", b"<n3t5yn4^n3tm0d>"),   # 16 bytes
    ("K2", b"_netsyna_netmod_"),   # 16 bytes
    ("K3", b"nicetrybuddygoon"),   # 17 bytes (decoy?)
]

# Load & decode base64
fname = sys.argv[1] if len(sys.argv) > 1 else 'ffft.nm'
with open(fname, 'r') as f:
    b64 = ''.join(f.read().split())

print(f"File: {fname}")
print(f"Base64 chars: {len(b64)}")
data = base64.b64decode(b64)
print(f"Decoded: {len(data)} bytes  (block-aligned: {len(data) % 16 == 0})")
print(f"First 16 bytes: {data[:16].hex()}")

# Duplicate block analysis (ECB hint)
blocks = [data[i:i+16] for i in range(0, len(data), 16)]
c = Counter(blocks)
dupes = [(b, n) for b, n in c.items() if n > 1]
print(f"Duplicate 16-byte blocks: {len(dupes)}")
if dupes:
    print("  → ECB HIGHLY LIKELY")
    for b, n in dupes[:3]:
        print(f"    {b.hex()} × {n}")
print()


def is_text(pt):
    """Check if decrypted bytes look like real text."""
    if not pt or len(pt) < 8:
        return None
    try:
        s = pt.decode('utf-8').rstrip('\x00')
        if len(s) < 8:
            return None
        printable = sum(1 for ch in s[:300] if ch.isprintable() or ch in '\n\r\t')
        ratio = printable / min(len(s), 300)
        if ratio > 0.80 and any(x in s for x in '{}[]:"=<>'):
            return s
    except Exception:
        pass
    return None


def report(label, pt):
    s = is_text(pt)
    if s:
        print(f"  ✓✓✓ {label}")
        print(f"       {s[:280]!r}")
        return True
    return False


found = False

for kname, key in KEYS:
    print("=" * 68)
    print(f"Key {kname}: {key!r}  ({len(key)} bytes)")
    print("=" * 68)

    # Skip non-AES sizes for symmetric AES
    if len(key) not in (16, 24, 32):
        # Try XOR
        x = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
        if report("XOR", x):
            found = True
        continue

    # AES-ECB (primary candidate — no IV)
    try:
        pt = AES.new(key, AES.MODE_ECB).decrypt(data)
        if report("AES-ECB (raw)", pt):
            found = True
        try:
            pt_un = unpad(pt, 16)
            if report("AES-ECB (unpadded)", pt_un):
                found = True
        except Exception:
            pass
    except Exception as e:
        print(f"  ECB error: {e}")

    # AES-CBC with various IVs
    for iv_name, iv in [
        ("zeros", b'\x00' * 16),
        ("key-as-iv", key[:16]),
        ("reverse-key", key[:16][::-1]),
        ("0xdb", b'\xdb' * 16),
    ]:
        try:
            pt = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(data)
            if report(f"AES-CBC/iv={iv_name}", pt):
                found = True
            try:
                if report(f"AES-CBC/iv={iv_name}+unpad", unpad(pt, 16)):
                    found = True
            except Exception:
                pass
        except Exception:
            pass

    # AES-CBC with IV = first block (decrypt from block 1)
    try:
        pt = AES.new(key, AES.MODE_CBC, iv=data[:16]).decrypt(data[16:])
        if report("AES-CBC/iv=first_block", pt):
            found = True
    except Exception:
        pass

    # AES-CFB-128
    for iv_name, iv in [("zeros", b'\x00' * 16), ("key", key[:16])]:
        try:
            pt = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(data)
            if report(f"AES-CFB128/iv={iv_name}", pt):
                found = True
        except Exception:
            pass

    # AES-CFB-8
    for iv_name, iv in [("zeros", b'\x00' * 16), ("key", key[:16])]:
        try:
            pt = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=8).decrypt(data)
            if report(f"AES-CFB8/iv={iv_name}", pt):
                found = True
        except Exception:
            pass

    # AES-OFB
    for iv_name, iv in [("zeros", b'\x00' * 16), ("key", key[:16])]:
        try:
            pt = AES.new(key, AES.MODE_OFB, iv=iv).decrypt(data)
            if report(f"AES-OFB/iv={iv_name}", pt):
                found = True
        except Exception:
            pass

    # AES-CTR
    for nonce in [b'\x00' * 8, key[:8]]:
        try:
            pt = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=0).decrypt(data)
            if report(f"AES-CTR/nonce={nonce.hex()}", pt):
                found = True
        except Exception:
            pass

    # XOR
    x = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    if report("XOR", x):
        found = True

    # ChaCha20 (pad key to 32 bytes)
    padded = (key * 3)[:32]
    for nonce_name, nonce in [
        ("zeros", b'\x00' * 8),
        ("0xdb", b'\xdb' * 8),
        ("data[:8]", data[:8]),
    ]:
        try:
            c = ChaCha20.new(key=padded, nonce=nonce)
            pt = c.decrypt(data)
            if report(f"ChaCha/nonce={nonce_name}", pt):
                found = True
        except Exception:
            pass
        try:
            c = ChaCha20.new(key=padded, nonce=nonce)
            pt = c.decrypt(data[:-16])   # strip poly1305 tag
            if report(f"ChaCha/nonce={nonce_name}/no-tag", pt):
                found = True
        except Exception:
            pass
    print()

# Two-layer attempt (K1 then K2, and reverse)
print("=" * 68)
print("DOUBLE-KEY (K1 ↔ K2 layered AES-ECB)")
print("=" * 68)
k1, k2 = KEYS[0][1], KEYS[1][1]
try:
    pt = AES.new(k1, AES.MODE_ECB).decrypt(data)
    pt = AES.new(k2, AES.MODE_ECB).decrypt(pt)
    if report("AES-ECB(K1) → AES-ECB(K2)", pt):
        found = True
except Exception:
    pass
try:
    pt = AES.new(k2, AES.MODE_ECB).decrypt(data)
    pt = AES.new(k1, AES.MODE_ECB).decrypt(pt)
    if report("AES-ECB(K2) → AES-ECB(K1)", pt):
        found = True
except Exception:
    pass

print()
print("=" * 68)
if found:
    print("✓✓✓ SUCCESS — copy the winning line's algorithm to NETMOD.py")
else:
    print("✗ None worked.")
    print("  Possible reasons:")
    print("   1. Algorithm is custom (Ghidra analysis of libgojni.so needed)")
    print("   2. Multi-layer or PBKDF2-derived key")
    print("   3. Decoy file / different format")
print("=" * 68)
