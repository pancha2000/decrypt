#!/usr/bin/env python3
"""Comprehensive HTTP Custom / Injector diagnostic."""
import sys, base64, re
from Crypto.Cipher import ChaCha20

# XOR keys to try
XOR_KEYS = [
    ("e382e4b8adc386f09f9293", "current in HTTPCUSTOM.py"),
    ("e382e4b8adc386f09f9293", "same (dup)"),
]

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
NONCE = b'\xdb' * 8


def xor(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def try_hex(s):
    try:
        s = s.decode('ascii').strip()
        if re.fullmatch(r'[0-9a-fA-F]+', s) and len(s) % 2 == 0:
            return bytes.fromhex(s)
    except: pass
    return None


def try_b64(s):
    try:
        s = s.decode('ascii').strip()
        if re.fullmatch(r'[A-Za-z0-9+/=]+', s) and len(s) % 4 == 0:
            return base64.b64decode(s)
    except: pass
    return None


def try_chacha(data, key, nonce, seek=64):
    try:
        c = ChaCha20.new(key=bytes.fromhex(key), nonce=nonce)
        if seek: c.seek(seek)
        return c.decrypt(data)
    except: return None


def unwrap_utf8(file_bytes):
    """UTF-8 decode → Latin-1 encode."""
    try:
        return file_bytes.decode('utf-8').encode('latin-1', errors='ignore')
    except:
        return None


def report_target(name, data):
    if not data: 
        print(f"\n[{name}] EMPTY"); return
    print(f"\n[{name}] {len(data)} bytes, first: {data[:20].hex()}")

    # Direct hex?
    if h := try_hex(data):
        print(f"  ✓ IS HEX directly ({len(h)} bytes)")
        for i, ck in enumerate(CHACHA_KEYS):
            pt = try_chacha(h, ck, NONCE, 64)
            if pt and (pt[:1] in (b'{', b'[')):
                print(f"    ✓✓ ChaCha KEY[{i}] → JSON: {pt[:100]!r}")

    # Direct base64?
    if b := try_b64(data):
        print(f"  ✓ IS BASE64 directly ({len(b)} bytes)")
    
    # XOR with each key
    for hex_key, desc in XOR_KEYS:
        try:
            key = bytes.fromhex(hex_key)
        except: continue
        xored = xor(data, key)
        if h := try_hex(xored):
            print(f"  ✓ XOR {hex_key} → HEX ({len(h)} bytes)")
            for i, ck in enumerate(CHACHA_KEYS):
                pt = try_chacha(h, ck, NONCE, 64)
                if pt and pt[:1] in (b'{', b'['):
                    print(f"    ✓✓ ChaCha KEY[{i}] → JSON: {pt[:150]!r}")
            continue
        if b := try_b64(xored):
            print(f"  ✓ XOR {hex_key} → BASE64 ({len(b)} bytes)")
            print(f"    Decoded: {b[:20].hex()}")
            continue
        printable = sum(1 for x in xored[:60] if 32 <= x < 127)
        print(f"  ✗ XOR {hex_key}: {printable}/60 printable")


def inspect(path):
    with open(path, 'rb') as f:
        raw = f.read()
    
    print("=" * 66)
    print(f"File: {path} ({len(raw)} bytes)")
    print("=" * 66)
    print(f"First 40 hex: {raw[:40].hex()}")
    print(f"Last 20 hex: {raw[-20:].hex()}")
    print(f"Valid UTF-8: ", end="")
    try:
        raw.decode('utf-8'); print("YES")
    except UnicodeDecodeError as e:
        print(f"NO (fail at byte {e.start})")
    
    # Detected encoding
    printable_ascii = sum(1 for b in raw if 32 <= b < 127)
    print(f"ASCII printable: {printable_ascii}/{len(raw)} = {printable_ascii/len(raw):.1%}")
    c2c3 = sum(1 for b in raw if b in (0xc2, 0xc3))
    print(f"UTF-8 lead bytes (c2/c3): {c2c3} ({c2c3/len(raw):.1%})")
    
    # Try RAW (as-is)
    report_target("RAW", raw)
    
    # Try unwrapped
    u = unwrap_utf8(raw)
    if u:
        print(f"\n[*] UTF-8 unwrap: {len(raw)} → {len(u)} bytes (lost {len(raw)-len(u)})")
        report_target("UNWRAPPED", u)
    
    # Try skipping headers
    print("\n" + "=" * 66)
    print("Skip-first-N-bytes + XOR test")
    print("=" * 66)
    for skip in (0, 1, 2, 4, 8, 16, 32):
        if skip >= len(raw): break
        for hex_key, desc in XOR_KEYS:
            try:
                key = bytes.fromhex(hex_key)
            except: continue
            xored = xor(raw[skip:], key)
            if h := try_hex(xored):
                print(f"  skip={skip:2d}: HEX! ({len(h)} bytes)")


if __name__ == "__main__":
    inspect(sys.argv[1] if len(sys.argv) > 1 else "ssst.hc")
