#!/usr/bin/env python3
"""Dark Tunnel config diagnostic tool — pinpoint exact failure."""
import sys
import base64
import json
from Crypto.Cipher import AES

try:
    import msgpack
    MSGPACK = True
except ImportError:
    MSGPACK = False
    print("[!] msgpack not installed — pip install msgpack")

KEY_256 = b"$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd"
KEY_192 = b"F)J@NcRfUjXn2r4u7x!A%D*G"
IV      = bytes.fromhex("232e39185523184a5723586242200e05")

MSGPACK_MAP = set(range(0x80, 0x90)) | {0xde, 0xdf}
MSGPACK_ARR = set(range(0x90, 0xa0)) | {0xdc, 0xdd}
MSGPACK_STR = set(range(0xa0, 0xc0)) | {0xd9, 0xda, 0xdb}


def b64d(s):
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def try_aes(data, key, iv):
    out = {}
    attempts = {
        "CFB-128": lambda: AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(data),
        "CFB-8":   lambda: AES.new(key, AES.MODE_CFB, iv=iv, segment_size=8).decrypt(data),
        "CBC":     lambda: AES.new(key, AES.MODE_CBC, iv=iv).decrypt(data),
        "OFB":     lambda: AES.new(key, AES.MODE_OFB, iv=iv).decrypt(data),
        "CTR":     lambda: AES.new(key, AES.MODE_CTR, nonce=b"",
                                   initial_value=int.from_bytes(iv[:8], "big")).decrypt(data),
    }
    for name, fn in attempts.items():
        try:
            out[name] = fn()
        except Exception as e:
            out[name] = f"ERROR: {e}"
    return out


def analyze(pt):
    if isinstance(pt, str):
        return pt
    if not pt:
        return "EMPTY"
    f = pt[0]
    info = [f"{len(pt)}B", f"first={f:#04x}"]
    if f in MSGPACK_MAP: info.append("MSGPACK-MAP")
    elif f in MSGPACK_ARR: info.append("MSGPACK-ARR")
    elif f in MSGPACK_STR: info.append("MSGPACK-STR")
    elif f == 0x7b: info.append("JSON?")
    elif f == 0x5b: info.append("JSON-ARR?")
    else: info.append("unknown")
    return "  ".join(info)


def try_msgpack(data):
    if not MSGPACK or isinstance(data, str):
        return False, "unavailable"
    try:
        return True, msgpack.unpackb(data, raw=False, strict_map_key=False)
    except Exception as e:
        return False, str(e)


def pipeline(text):
    print("\n" + "=" * 72 + "\nSTEP 1: Strip scheme\n" + "=" * 72)
    raw = text.strip()
    if "://" in raw:
        scheme = raw.split("://", 1)[0]
        raw = raw.split("://", 1)[1]
        print(f"  Scheme: {scheme}://  → stripped")

    print("\n" + "=" * 72 + "\nSTEP 2: Base64 decode (outer)\n" + "=" * 72)
    try:
        ob = b64d(raw)
        print(f"  ✓ {len(ob)} bytes")
    except Exception as e:
        print(f"  ✗ FAILED: {e}"); return

    print("\n" + "=" * 72 + "\nSTEP 3: JSON parse (outer)\n" + "=" * 72)
    try:
        outer = json.loads(ob.decode("utf-8"))
        print(f"  ✓ Keys: {list(outer.keys())}")
    except Exception as e:
        print(f"  ✗ FAILED: {e}"); return

    if "encryptedLockedConfig" not in outer:
        print(f"  ✗ field missing"); return
    print(f"  ✓ 'encryptedLockedConfig' present")

    if "trojanTunnelConfig" in outer:
        print(f"\n  [trojanTunnelConfig] (plaintext):")
        print(f"  {json.dumps(outer['trojanTunnelConfig'], indent=2)[:400]}")

    print("\n" + "=" * 72 + "\nSTEP 4: Base64 decode encryptedLockedConfig\n" + "=" * 72)
    try:
        enc_val = outer["encryptedLockedConfig"]
        enc = b64d(enc_val) if isinstance(enc_val, str) else enc_val
        print(f"  ✓ {len(enc)} bytes  (len % 16 = {len(enc) % 16})")
    except Exception as e:
        print(f"  ✗ FAILED: {e}"); return

    print("\n" + "=" * 72 + "\nSTEP 5: KEY_256 attempts\n" + "=" * 72)
    results = try_aes(enc, KEY_256, IV)
    winner = None
    for mode, pt in results.items():
        print(f"  {mode:8s}: {analyze(pt)}")
        if not isinstance(pt, str):
            ok, val = try_msgpack(pt)
            if ok:
                print(f"           ✓✓✓ MSGPACK OK: "
                      f"keys={list(val.keys()) if isinstance(val, dict) else type(val).__name__}")
                if winner is None:
                    winner = (mode, pt)
            else:
                print(f"           msgpack: {val}")

    if winner is None:
        print("\n  ✗ NO mode succeeded for outer layer"); return
    print(f"\n  ✓ OUTER DECRYPTED with mode = {winner[0]}")

    unpacked = msgpack.unpackb(winner[1], raw=False, strict_map_key=False)

    if isinstance(unpacked, dict) and "EncryptedLockedConfig" in unpacked:
        print("\n" + "=" * 72 + "\nSTEP 6: Inner layer\n" + "=" * 72)
        inner = unpacked["EncryptedLockedConfig"]
        if isinstance(inner, str):
            inner = inner.encode("latin1")
        print(f"  Inner encrypted: {len(inner)} bytes")
        for mode, pt in try_aes(inner, KEY_192, IV).items():
            print(f"  {mode:8s}: {analyze(pt)}")
            if not isinstance(pt, str):
                ok, val = try_msgpack(pt)
                if ok:
                    print(f"           ✓✓✓ INNER MSGPACK OK: "
                          f"keys={list(val.keys()) if isinstance(val, dict) else type(val).__name__}")

    print("\n" + "=" * 72 + "\nDONE\n" + "=" * 72)


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        with open(sys.argv[1], "rb") as f:
            pipeline(f.read().decode("utf-8", errors="ignore"))
    else:
        print("Paste darktunnel:// input, then Ctrl+D:")
        pipeline(sys.stdin.read())
