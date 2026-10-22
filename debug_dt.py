#!/usr/bin/env python3
"""
DARK TUNNEL config diagnostic tool
- Detects exact failure point
- Tries all AES modes (CFB-128, CFB-8, CBC, OFB, CTR)
- Tries both keys (KEY_256 outer, KEY_192 inner)
- Shows msgpack vs non-msgpack content
"""
import sys
import base64
import json
from Crypto.Cipher import AES

try:
    import msgpack
    MSGPACK = True
except ImportError:
    MSGPACK = False
    print("[!] msgpack not installed — install with: pip install msgpack")


# === Constants ===
KEY_256 = b"$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd"
KEY_192 = b"F)J@NcRfUjXn2r4u7x!A%D*G"
IV      = bytes.fromhex("232e39185523184a5723586242200e05")

MSGPACK_MAP_MARKERS = set(range(0x80, 0x90)) | {0xde, 0xdf}   # map8/16/32
MSGPACK_ARR_MARKERS = set(range(0x90, 0xa0)) | {0xdc, 0xdd}   # arr8/16/32
MSGPACK_STR_MARKERS = set(range(0xa0, 0xc0)) | {0xd9, 0xda, 0xdb}


def b64d(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def try_aes(data: bytes, key: bytes, iv: bytes):
    """Try all AES modes. Returns dict {mode: plaintext_or_error}."""
    out = {}
    attempts = {
        "CFB-128": lambda: AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(data),
        "CFB-8":   lambda: AES.new(key, AES.MODE_CFB, iv=iv, segment_size=8).decrypt(data),
        "CBC":     lambda: AES.new(key, AES.MODE_CBC, iv=iv).decrypt(data),
        "OFB":     lambda: AES.new(key, AES.MODE_OFB, iv=iv).decrypt(data),
        "CTR":     lambda: AES.new(key, AES.MODE_CTR,
                                   nonce=b"",
                                   initial_value=int.from_bytes(iv[:8], "big")).decrypt(data),
    }
    for name, fn in attempts.items():
        try:
            out[name] = fn()
        except Exception as e:
            out[name] = f"ERROR: {e}"
    return out


def analyze(pt: bytes) -> str:
    """Describe decoded bytes."""
    if isinstance(pt, str):
        return pt
    if not pt:
        return "EMPTY"
    first = pt[0]
    info = [f"{len(pt)}B", f"first={first:#04x}"]
    if first in MSGPACK_MAP_MARKERS:
        info.append("MSGPACK-MAP")
    elif first in MSGPACK_ARR_MARKERS:
        info.append("MSGPACK-ARR")
    elif first in MSGPACK_STR_MARKERS:
        info.append("MSGPACK-STR")
    elif first == 0x7b:
        info.append("JSON?")
    elif first == 0x5b:
        info.append("JSON-ARR?")
    else:
        info.append("unknown")
    return "  ".join(info)


def try_msgpack(data: bytes):
    """Return (success_bool, result_or_error)."""
    if not MSGPACK or isinstance(data, str):
        return False, "msgpack unavailable"
    try:
        return True, msgpack.unpackb(data, raw=False, strict_map_key=False)
    except Exception as e:
        return False, str(e)


def full_pipeline(input_text: str):
    print("\n" + "=" * 72)
    print("STEP 1: Strip scheme")
    print("=" * 72)
    raw = input_text.strip()
    if "://" in raw:
        scheme = raw.split("://", 1)[0]
        raw = raw.split("://", 1)[1]
        print(f"  Scheme: {scheme}://  → stripped")
    else:
        print("  No scheme found")

    print("\n" + "=" * 72)
    print("STEP 2: Base64 decode (outer)")
    print("=" * 72)
    try:
        outer_bytes = b64d(raw)
        print(f"  ✓ {len(outer_bytes)} bytes")
        print(f"  First 40 hex: {outer_bytes[:40].hex()}")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        return

    print("\n" + "=" * 72)
    print("STEP 3: JSON parse (outer)")
    print("=" * 72)
    try:
        outer = json.loads(outer_bytes.decode("utf-8"))
        print(f"  ✓ JSON OK. Keys: {list(outer.keys())}")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        print(f"  Raw: {outer_bytes[:200]!r}")
        return

    if "encryptedLockedConfig" not in outer:
        print(f"  ✗ 'encryptedLockedConfig' NOT FOUND")
        return
    print(f"  ✓ 'encryptedLockedConfig' present")

    # Optional: show plaintext trojanTunnelConfig
    if "trojanTunnelConfig" in outer:
        print(f"\n  [trojanTunnelConfig] (plaintext — no decrypt needed):")
        print(f"  {json.dumps(outer['trojanTunnelConfig'], indent=2)[:400]}")

    print("\n" + "=" * 72)
    print("STEP 4: Base64 decode encryptedLockedConfig")
    print("=" * 72)
    enc_val = outer["encryptedLockedConfig"]
    try:
        enc = b64d(enc_val) if isinstance(enc_val, str) else enc_val
        print(f"  ✓ {len(enc)} bytes")
        print(f"  First 32 hex: {enc[:32].hex()}")
        print(f"  len % 16 = {len(enc) % 16}  (0 → CBC/block aligned, 12/16 → GCM, else → CFB/CTR)")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        return

    print("\n" + "=" * 72)
    print("STEP 5: KEY_256 decryption attempts")
    print("=" * 72)
    results_outer = try_aes(enc, KEY_256, IV)
    winning_mode = None
    winning_pt = None
    for mode, pt in results_outer.items():
        desc = analyze(pt)
        print(f"  {mode:8s}: {desc}")
        if not isinstance(pt, str):
            ok, val = try_msgpack(pt)
            if ok:
                print(f"           ✓✓✓ MSGPACK OK: keys={list(val.keys()) if isinstance(val, dict) else type(val).__name__}")
                if winning_mode is None:
                    winning_mode = mode
                    winning_pt = pt
            else:
                print(f"           msgpack: {val}")
                print(f"           first 80: {pt[:80]!r}")

    if winning_pt is None:
        print("\n  ✗ NO mode succeeded for outer layer")
        # Show raw attempt output to help debugging
        print("\n  [RAW HEX of each mode — first 80 bytes]")
        for mode, pt in results_outer.items():
            if not isinstance(pt, str):
                print(f"    {mode}: {pt[:80].hex()}")
        return

    print(f"\n  ✓ OUTER LAYER DECRYPTED with mode = {winning_mode}")
    unpacked = msgpack.unpackb(winning_pt, raw=False, strict_map_key=False)
    if isinstance(unpacked, dict):
        print(f"  Outer msgpack keys: {list(unpacked.keys())}")

    # ========== INNER LAYER ==========
    if isinstance(unpacked, dict) and "EncryptedLockedConfig" in unpacked:
        print("\n" + "=" * 72)
        print("STEP 6: Inner layer (EncryptedLockedConfig)")
        print("=" * 72)
        inner_enc = unpacked["EncryptedLockedConfig"]
        if isinstance(inner_enc, str):
            inner_enc = inner_enc.encode("latin1")
        print(f"  Inner encrypted: {len(inner_enc)} bytes")

        results_inner = try_aes(inner_enc, KEY_192, IV)
        for mode, pt in results_inner.items():
            desc = analyze(pt)
            print(f"  {mode:8s}: {desc}")
            if not isinstance(pt, str):
                ok, val = try_msgpack(pt)
                if ok:
                    print(f"           ✓✓✓ INNER MSGPACK OK: keys={list(val.keys()) if isinstance(val, dict) else type(val).__name__}")
                else:
                    print(f"           msgpack: {val}")

    print("\n" + "=" * 72)
    print("DONE")
    print("=" * 72)


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        with open(sys.argv[1], "rb") as f:
            text = f.read().decode("utf-8", errors="ignore")
    else:
        print("Paste darktunnel:// input, then Ctrl+D:")
        text = sys.stdin.read()
    full_pipeline(text)
