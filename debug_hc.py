#!/usr/bin/env python3
"""HTTP Custom .hc diagnostic."""
import sys, base64, json, re
from Crypto.Cipher import ChaCha20

XOR_KEY_HEX = "e382e4b8adc386f09f9293"
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


def inspect(path):
    with open(path, 'rb') as f:
        raw = f.read()
    print(f"File: {path}  ({len(raw)} bytes)")
    print(f"First 40 hex: {raw[:40].hex()}")
    print(f"First 40 ascii: {raw[:40]!r}")
    print(f"All ASCII: {all(b < 0x80 for b in raw)}")

    key = bytes.fromhex(XOR_KEY_HEX)

    print("\n" + "=" * 60)
    print("[A] Lossy conversion (ORIGINAL code behavior)")
    print("=" * 60)
    try:
        lossy = raw.decode('utf-8', errors='ignore').encode('latin-1', errors='ignore')
        print(f"  Original {len(raw)} → Lossy {len(lossy)} bytes  (LOST {len(raw) - len(lossy)})")
        x = xor(lossy, key)
        try:
            s = x.decode('ascii')
            print(f"  XOR result ASCII (first 60): {s[:60]!r}")
            is_hex = bool(re.fullmatch(r'[0-9a-fA-F]+', s))
            print(f"  All hex: {is_hex}")
        except UnicodeDecodeError:
            print(f"  XOR result non-ASCII, hex: {x[:40].hex()}")
    except Exception as e:
        print(f"  Error: {e}")

    print("\n" + "=" * 60)
    print("[B] Raw bytes XOR (FIXED behavior)")
    print("=" * 60)
    x = xor(raw, key)
    try:
        s = x.decode('ascii')
        print(f"  XOR result ASCII (first 60): {s[:60]!r}")
        is_hex = bool(re.fullmatch(r'[0-9a-fA-F]+', s))
        print(f"  All hex: {is_hex}")
        if is_hex:
            ct = bytes.fromhex(s if len(s) % 2 == 0 else '0' + s)
            print(f"  Ciphertext: {len(ct)} bytes")
            print("\n  --- Trying all 8 ChaCha keys with static nonce ---")
            for idx, kh in enumerate(CHACHA_KEYS):
                for skip in (64, 0):
                    try:
                        c = ChaCha20.new(key=bytes.fromhex(kh), nonce=NONCE)
                        if skip:
                            c.seek(skip)
                        pt = c.decrypt(ct[:-16] if len(ct) > 16 else ct)
                        if pt[:1] in (b'{', b'['):
                            print(f"  ✓✓ KEY[{idx}] skip={skip}: JSON! {pt[:100]!r}")
                        elif idx == 5 and skip == 64:
                            print(f"  KEY[5] skip=64: {pt[:40]!r}")
                    except Exception:
                        pass
    except UnicodeDecodeError:
        print(f"  Non-ASCII output, hex: {x[:60].hex()}")

    print("\n" + "=" * 60)
    print("[C] Is file already plaintext / JSON / base64?")
    print("=" * 60)
    try:
        json.loads(raw.decode('utf-8'))
        print("  ✓ File IS plain JSON")
    except: pass
    try:
        s = raw.decode('ascii').strip()
        if re.fullmatch(r'[0-9a-fA-F]+', s):
            print(f"  File IS hex ({len(s)} chars)")
        elif re.fullmatch(r'[A-Za-z0-9+/=_-]+', s):
            print(f"  File IS base64-ish ({len(s)} chars)")
            d = base64.b64decode(s.replace('-', '+').replace('_', '/') + '=' * ((4 - len(s) % 4) % 4))
            print(f"  Decoded: {len(d)} bytes, first 30: {d[:30]!r}")
    except: pass


if __name__ == "__main__":
    inspect(sys.argv[1] if len(sys.argv) > 1 else "ssst.hc")
