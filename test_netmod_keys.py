#!/usr/bin/env python3
"""Test NetMod candidate keys against a config file."""
import sys, base64, re, hashlib
from Crypto.Cipher import AES, ChaCha20
from Crypto.Util.Padding import unpad

CANDIDATES = [
    b"<n3t5yn4^n3tm0d>",   # 16 bytes → AES-128
    b"_netsyna_netmod_",   # 16 bytes → AES-128
    b"n3t5yn4^n3tm0d",     # 14 bytes → PBKDF2 password
    b"netsyna_netmod",     # 14 bytes → PBKDF2 password
    b"nicetrybuddygoon",   # 17 bytes → DECOY (test only, expect fail)
]

# IVs to try
IVS = [
    ("HC-IV", bytes.fromhex("232e39185523184a5723586242200e05")),
    ("zeros", b'\x00' * 16),
    ("0xdb*16", b'\xdb' * 16),
]

MSGPACK_MARKERS = set(range(0x80, 0x90)) | {0xde, 0xdf}


def looks_interesting(pt):
    """Return True if output looks like decrypted content."""
    if not pt or len(pt) < 4:
        return False
    # JSON
    if pt[:1] in (b'{', b'['):
        return True
    # msgpack map
    if pt[0] in MSGPACK_MARKERS:
        return True
    # Hex text
    try:
        s = pt[:200].decode('ascii')
        if re.fullmatch(r'[0-9a-fA-F\s]+', s) and len(s.strip()) >= 32:
            return True
    except:
        pass
    # Readable UTF-8 text
    try:
        s = pt[:100].decode('utf-8')
        printable = sum(1 for c in s if c.isprintable() or c in '\t\n\r')
        if len(s) > 20 and printable / len(s) > 0.9:
            return True
    except:
        pass
    return False


def preview(pt, n=100):
    try:
        return pt[:n].decode('utf-8', errors='replace')
    except:
        return pt[:n].hex()


def try_aes(data, key):
    """Try all AES modes with multiple IVs."""
    hits = []
    block_aligned = len(data) // 16 * 16
    for iv_name, iv in IVS:
        for mode_name, mode in [("CBC", AES.MODE_CBC), ("CFB-128", AES.MODE_CFB),
                                 ("CFB-8", None), ("OFB", AES.MODE_OFB),
                                 ("CTR", AES.MODE_CTR)]:
            try:
                if mode == AES.MODE_CTR:
                    pt = AES.new(key, mode, nonce=b'',
                                 initial_value=int.from_bytes(iv[:8], 'big')).decrypt(data)
                elif mode_name == "CFB-8":
                    pt = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=8).decrypt(data)
                else:
                    pt = AES.new(key, mode, iv=iv).decrypt(block_aligned if mode != AES.MODE_CFB and mode != AES.MODE_OFB and mode != AES.MODE_CTR else data)
                if looks_interesting(pt):
                    hits.append((f"AES-{mode_name}", iv_name, pt))
            except Exception:
                pass
    # ECB
    try:
        pt = AES.new(key, AES.MODE_ECB).decrypt(block_aligned)
        if looks_interesting(pt):
            hits.append(("AES-ECB", "-", pt))
    except:
        pass
    return hits


def try_xor(data, key):
    """XOR with repeating key."""
    x = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    if looks_interesting(x):
        return x
    return None


def try_chacha(data, key_bytes, nonce):
    """ChaCha20 needs 32-byte key + 8-byte nonce."""
    if len(key_bytes) != 32:
        return []
    hits = []
    for seek in (0, 64):
        try:
            c = ChaCha20.new(key=key_bytes, nonce=nonce)
            if seek:
                c.seek(seek)
            pt = c.decrypt(data[:-16] if len(data) > 16 else data)
            if looks_interesting(pt):
                hits.append((f"ChaCha seek={seek}", pt))
        except:
            pass
    return hits


def try_pbkdf2(data, password):
    """Derive AES-128 key via PBKDF2 (common salt variants)."""
    hits = []
    for salt in [b'', b'netsyna', b'netmod', b'_netsyna_netmod_',
                 b'<n3t5yn4^n3tm0d>', password]:
        for iters in (1, 1000, 10000):
            try:
                key = hashlib.pbkdf2_hmac('sha256', password, salt, iters, dklen=16)
                for iv_name, iv in IVS[:2]:
                    for mode_name, mode in [("CBC", AES.MODE_CBC), ("CFB-128", AES.MODE_CFB)]:
                        try:
                            if mode_name == "CFB-128":
                                pt = AES.new(key, mode, iv=iv, segment_size=128).decrypt(data)
                            else:
                                pt = AES.new(key, mode, iv=iv).decrypt(len(data)//16*16)
                            if looks_interesting(pt):
                                hits.append((f"PBKDF2-{mode_name} iters={iters} salt={salt!r}", pt))
                        except:
                            pass
            except:
                pass
    return hits


# ============ Main ============
with open(sys.argv[1], 'rb') as f:
    raw = f.read()

print(f"File: {len(raw)} bytes")
print(f"First 20 hex: {raw[:20].hex()}")
print()

# Data variants
data_variants = [("raw", raw)]
try:
    unwrapped = bytes(ord(c) & 0xFF for c in raw.decode('utf-8'))
    if unwrapped != raw:
        data_variants.append(("unwrapped", unwrapped))
        print(f"Unwrapped: {len(unwrapped)} bytes")
except:
    pass

# Also try base64/hex decode first
for label, d in list(data_variants):
    try:
        s = d.decode('ascii').strip()
        if re.fullmatch(r'[0-9a-fA-F]+', s) and len(s) % 2 == 0:
            data_variants.append((f"{label}_hexdecoded", bytes.fromhex(s)))
        elif re.fullmatch(r'[A-Za-z0-9+/=]+', s) and len(s) % 4 == 0:
            data_variants.append((f"{label}_b64decoded", base64.b64decode(s)))
    except:
        pass

print(f"Data variants: {[n for n, _ in data_variants]}\n")

any_success = False

for data_name, data in data_variants:
    print(f"\n{'='*66}")
    print(f"=== {data_name} ({len(data)} bytes) ===")
    print('='*66)

    for cand in CANDIDATES:
        print(f"\n[Key: {cand!r}  ({len(cand)} bytes)]")

        # 1) Direct AES (16/24/32 bytes)
        if len(cand) in (16, 24, 32):
            hits = try_aes(data, cand)
            for mode, iv, pt in hits:
                print(f"  ✓✓ {mode} iv={iv}")
                print(f"      {preview(pt)}")
                any_success = True
            if not hits:
                print(f"  ✗ AES: no match")

        # 2) XOR
        x = try_xor(data, cand)
        if x:
            print(f"  ✓✓ XOR: {preview(x)}")
            any_success = True
        else:
            print(f"  ✗ XOR: no match")

        # 3) ChaCha20 (needs 32 bytes; pad if short)
        if len(cand) <= 32:
            padded = (cand * 3)[:32]
            for nonce_name, nonce in [("0xdb*8", b'\xdb' * 8),
                                       ("zeros", b'\x00' * 8),
                                       ("data[:8]", data[:8])]:
                hits = try_chacha(data, padded, nonce)
                for mode, pt in hits:
                    print(f"  ✓✓ {mode} nonce={nonce_name}")
                    print(f"      {preview(pt)}")
                    any_success = True

        # 4) PBKDF2
        hits = try_pbkdf2(data, cand)
        for mode, pt in hits:
            print(f"  ✓✓ {mode}")
            print(f"      {preview(pt)}")
            any_success = True

print("\n" + "=" * 66)
if any_success:
    print("✓✓✓ At least one key worked — check output above!")
else:
    print("✗ No key worked on any data variant.")
    print("  → Keys may be markers, not actual keys")
    print("  → Or wrong file format")
    print("  → Try checking WHERE these strings are used in the binary")
print("=" * 66)
