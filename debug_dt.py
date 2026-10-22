import json
import base64
from Crypto.Cipher import AES
import msgpack

KEY_256 = b"$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd"
KEY_192 = b"F)J@NcRfUjXn2r4u7x!A%D*G"
IV = bytes.fromhex("232e39185523184a5723586242200e05")


def b64d(s):
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def try_decrypt(data, key, iv):
    """Try all AES modes and return first that looks like msgpack"""
    results = {}
    modes = {
        "CFB-128": lambda: AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(data),
        "CFB-8":   lambda: AES.new(key, AES.MODE_CFB, iv=iv, segment_size=8).decrypt(data),
        "CBC":     lambda: AES.new(key, AES.MODE_CBC, iv=iv).decrypt(data),
        "OFB":     lambda: AES.new(key, AES.MODE_OFB, iv=iv).decrypt(data),
        "CTR":     lambda: AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(iv[:8], "big")).decrypt(data),
    }
    for name, fn in modes.items():
        try:
            pt = fn()
            results[name] = pt
        except Exception as e:
            results[name] = f"ERR: {e}"
    return results


def is_msgpack_like(data):
    """msgpack starts with a map (0x80-0x8f) or other known marker"""
    if not data or len(data) < 1:
        return False
    return data[0] in (0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                       0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                       0xde, 0xdf)  # map16, map32


# ============ MAIN ============
with open("ddy.dark", "rb") as f:
    raw = f.read().decode("utf-8", errors="ignore").strip()

print("=" * 70)
print("[STEP 1] Strip scheme")
print("=" * 70)
if "://" in raw:
    raw = raw.split("://", 1)[1]
print(f"  Length after strip: {len(raw)}")

print("\n" + "=" * 70)
print("[STEP 2] Base64 decode outer")
print("=" * 70)
decoded = b64d(raw)
print(f"  Decoded: {len(decoded)} bytes")

print("\n" + "=" * 70)
print("[STEP 3] JSON parse")
print("=" * 70)
outer = json.loads(decoded.decode("utf-8"))
print(f"  Keys: {list(outer.keys())}")

# Check trojanTunnelConfig (should be plaintext)
if "trojanTunnelConfig" in outer:
    print(f"\n  [trojanTunnelConfig] (plaintext?):")
    print(f"  {json.dumps(outer['trojanTunnelConfig'], indent=2)[:500]}")

# Get encryptedLockedConfig
enc_locked = outer["encryptedLockedConfig"]
print(f"\n  encryptedLockedConfig type: {type(enc_locked)}")
print(f"  encryptedLockedConfig value (first 100 chars): {str(enc_locked)[:100]}")

print("\n" + "=" * 70)
print("[STEP 4] Base64 decode encryptedLockedConfig")
print("=" * 70)
if isinstance(enc_locked, str):
    enc_bytes = b64d(enc_locked)
else:
    enc_bytes = enc_locked  # already bytes
print(f"  Encrypted blob: {len(enc_bytes)} bytes")
print(f"  First 32 hex: {enc_bytes[:32].hex()}")
print(f"  Length % 16: {len(enc_bytes) % 16}")

print("\n" + "=" * 70)
print("[STEP 5] Try KEY_256 with all modes")
print("=" * 70)
results = try_decrypt(enc_bytes, KEY_256, IV)
for mode, pt in results.items():
    if isinstance(pt, str):
        print(f"  {mode}: {pt}")
    else:
        mp_like = is_msgpack_like(pt)
        print(f"  {mode}: {len(pt)} bytes, first byte: {pt[0]:#04x}, "
              f"msgpack-like: {mp_like}")
        if mp_like:
            try:
                unpacked = msgpack.unpackb(pt, raw=False, strict_map_key=False)
                print(f"    ✓✓✓ MSGPACK SUCCESS! Keys: {list(unpacked.keys()) if isinstance(unpacked, dict) else type(unpacked)}")
                # Try inner layer
                if isinstance(unpacked, dict) and "EncryptedLockedConfig" in unpacked:
                    print(f"    Inner 'EncryptedLockedConfig' found!")
                    inner_enc = unpacked["EncryptedLockedConfig"]
                    print(f"    Inner encrypted: {len(inner_enc)} bytes")
                    inner_results = try_decrypt(inner_enc, KEY_192, IV)
                    for imode, ipt in inner_results.items():
                        if isinstance(ipt, str):
                            continue
                        imp_like = is_msgpack_like(ipt)
                        print(f"      {imode}: msgpack-like: {imp_like}")
                        if imp_like:
                            try:
                                inner = msgpack.unpackb(ipt, raw=False, strict_map_key=False)
                                print(f"      ✓✓✓ INNER MSGPACK SUCCESS! Keys: {list(inner.keys()) if isinstance(inner, dict) else type(inner)}")
                            except Exception as e:
                                print(f"      msgpack fail: {e}")
            except Exception as e:
                print(f"    msgpack fail: {e}")
            print(f"    Raw (first 100): {pt[:100]!r}")
