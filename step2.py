#!/usr/bin/env python3
"""Step 2: try every decryption path on the 1849-byte underlying data."""
import sys, base64, re, json
from Crypto.Cipher import ChaCha20, AES
from Crypto.Util.Padding import unpad

# Constants from HTTPCUSTOM.py
CHACHA_KEYS = [
    "2be4342943c6f91ff58987f41a1aafd179eeb4e053f5cea55b11d6a7db58bd7d",
    "3380aa278b744ba5b529a7f32fa803e48749280dae378345d9b526cf1dbce372",
    "cea9305c95168b162a335b137c61983b8df54e6375da01136547890f14c5fac3",
    "4beeace0e42bae8f29470cf40cf2dfacd5f4e1f751912bf52e803c8c85792193",
    "f8e5f6ebea90558eb32229da24fd0fb7d813091dafe89bb2954fda33b4c60f63",
    "81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c",
    "45635e6fc70486e2fd10d3c2b4780f02d0b4c5f4aa929fc54f86bb8fa4417944",
    "3d632a251c9820f2baf83e15498d27548fc67921cb437f8ce48505989378adea",
]
RST_KEYS = [
    b"JN1k3YHc2.6_v235", b"JN1k3YHc_2.7_v71", b"JN1k3YHc2.7.ps69",
    b"JN1k3YHc2.7.6950", b"Jn1K3yHc2.8.ps08", b"Jn1K3yHc2.9.ps6c",
    b"Zk:L7>WKaiK*s9>D", b"!<f!&WIlM**R.B0X", b"b4a5opinx2uloec6",
]
STATIC_NONCE = b'\xdb' * 8
RST_XOR_KEY = bytes(range(2, 22))


def xor(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def is_json(b):
    if not b or not isinstance(b, (bytes, bytearray)): return False
    try:
        s = b.decode('utf-8').strip()
        return s.startswith(('{', '[')) and s.endswith(('}', ']'))
    except: return False


def preview(b, n=80):
    if isinstance(b, bytes):
        try: return b[:n].decode('utf-8', errors='replace')
        except: return b[:n].hex()
    return str(b)[:n]


def try_chacha(data, key_hex, nonce, seek=64, skip_tag=True):
    try:
        c = ChaCha20.new(key=bytes.fromhex(key_hex), nonce=nonce)
        if seek: c.seek(seek)
        payload = data[:-16] if (skip_tag and len(data) > 16) else data
        return c.decrypt(payload)
    except Exception:
        return None


with open(sys.argv[1], 'rb') as f:
    raw = f.read()

# Recover 1849-byte underlying data
unwrapped = bytes(ord(c) & 0xFF for c in raw.decode('utf-8'))
print(f"File: {len(raw)} bytes → underlying: {len(unwrapped)} bytes\n")


def test_chacha_direct(label, data):
    print(f"\n[{label}] {len(data)} bytes, first hex: {data[:20].hex()}")
    hit = False
    # 8-byte nonce variants
    for nonce_name, nonce in [
        ("b'\\xdb'*8", STATIC_NONCE),
        ("zeros*8", b'\x00' * 8),
        ("data[-8:]", data[-8:]),
        ("data[:8]", data[:8]),
    ]:
        for key_idx, kh in enumerate(CHACHA_KEYS):
            for seek in (64, 0):
                pt = try_chacha(data, kh, nonce, seek=seek)
                if pt and is_json(pt):
                    print(f"  ✓✓ KEY[{key_idx}] nonce={nonce_name} seek={seek}")
                    print(f"      {preview(pt, 120)}")
                    hit = True
    if not hit:
        print(f"  ✗ No direct ChaCha20 match")


def test_rst(data):
    print(f"\n[RST test] {len(data)} bytes")
    try:
        xored = xor(data, RST_XOR_KEY)
        # Try base64 decode of xored
        try:
            ct = base64.b64decode(xored, validate=False)
            print(f"  XOR+b64 → {len(ct)} bytes")
            for i, k in enumerate(RST_KEYS):
                try:
                    pt = unpad(AES.new(k, AES.MODE_ECB).decrypt(ct), AES.block_size)
                    s = pt.decode('utf-8', errors='ignore')
                    if "[splitConfig]" in s or s.strip().startswith(('{', '[')):
                        print(f"  ✓✓ RST KEY[{i}] → {preview(pt, 120)}")
                except Exception:
                    pass
        except Exception as e:
            print(f"  b64 decode failed: {e}")
    except Exception as e:
        print(f"  error: {e}")


def test_hex_or_b64(label, data):
    print(f"\n[{label}] check if it's hex or base64")
    try:
        s = data.decode('ascii').strip()
        if re.fullmatch(r'[0-9a-fA-F]+', s) and len(s) % 2 == 0:
            print(f"  ✓ IS HEX → {len(s)//2} bytes: {bytes.fromhex(s)[:20].hex()}")
            return
    except: pass
    try:
        s = data.decode('ascii').strip()
        if re.fullmatch(r'[A-Za-z0-9+/=]+', s) and len(s) % 4 == 0:
            d = base64.b64decode(s)
            print(f"  ✓ IS BASE64 → {len(d)} bytes: {d[:20].hex()}")
            return
    except: pass
    print(f"  ✗ Neither hex nor base64")


# ============ TESTS ============
print("=" * 66)
print("TEST 1: is unwrapped data hex/base64?")
print("=" * 66)
test_hex_or_b64("unwrapped", unwrapped)

print("\n" + "=" * 66)
print("TEST 2: direct ChaCha20 on unwrapped (NO XOR)")
print("=" * 66)
test_chacha_direct("unwrapped", unwrapped)

print("\n" + "=" * 66)
print("TEST 3: RST scheme (XOR + b64 + AES-ECB)")
print("=" * 66)
test_rst(unwrapped)

print("\n" + "=" * 66)
print("TEST 4: ChaCha20 on raw file bytes (NO unwrap)")
print("=" * 66)
test_chacha_direct("raw", raw)

print("\n" + "=" * 66)
print("DONE")
print("=" * 66)
