#!/usr/bin/env python3
"""NetMod link decoder — reads from file to avoid terminal stripping."""
import sys
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

KEY = b"<n3t5yn4^n3tm0d>"

if len(sys.argv) < 2:
    print("Usage: python decode_link_file.py <link_file>")
    print("Example: python decode_link_file.py vless_link.txt")
    sys.exit(1)

with open(sys.argv[1], "rb") as f:
    raw = f.read()

# Strip whitespace, newlines
text = raw.decode("utf-8", errors="ignore").strip()
print(f"File size: {len(raw)} bytes")
print(f"Stripped: {len(text)} chars")
print(f"First 30 chars: {text[:30]!r}")
print(f"Last 30 chars : {text[-30:]!r}")

# Strip scheme
if "://" not in text:
    print("✗ No scheme")
    sys.exit(1)

scheme, payload = text.split("://", 1)
payload = payload.split("?")[0].split("#")[0].strip()

print(f"\nScheme: {scheme}")
print(f"Payload: {len(payload)} chars")
print(f"Payload % 4 = {len(payload) % 4}")
print(f"Expected decoded bytes: {len(payload) * 3 // 4}")
print(f"Expected aligned: {(len(payload) * 3 // 4) % 16 == 0}")

# Base64 decode with auto-pad
b64 = payload.replace("-", "+").replace("_", "/")
pad_needed = (4 - len(b64) % 4) % 4
b64_padded = b64 + "=" * pad_needed
print(f"Padding added: {pad_needed} '='")

try:
    data = base64.b64decode(b64_padded)
except Exception as e:
    print(f"✗ base64 decode failed: {e}")
    sys.exit(1)

print(f"Decoded: {len(data)} bytes  (align: {len(data) % 16})")
print(f"First 16 hex: {data[:16].hex()}")
print(f"Last  16 hex: {data[-16:].hex()}")
print()


def is_readable(b):
    if not b or len(b) < 8:
        return False
    try:
        s = b.decode("utf-8")
        if len(s) < 8:
            return False
        printable = sum(1 for c in s[:300] if c.isprintable() or c in '\n\r\t')
        return printable / min(len(s), 300) > 0.85
    except UnicodeDecodeError:
        return False


def try_decrypt(label, ct):
    if len(ct) % 16 != 0 or len(ct) < 16:
        return False
    try:
        pt = AES.new(KEY, AES.MODE_ECB).decrypt(ct)
    except Exception as e:
        return False

    # Try unpad
    for suffix, cand in [
        ("unpadded", None),
        ("raw-strip", pt.rstrip(b"\x00")),
        ("full", pt),
    ]:
        if suffix == "unpadded":
            try:
                cand = unpad(pt, 16)
            except Exception:
                continue
        if is_readable(cand):
            print(f"✓✓✓ {label} [{suffix}]")
            try:
                s = cand.decode("utf-8")
            except:
                s = cand.decode("latin-1", errors="replace")
            print(f"\n{'='*60}\nDECRYPTED CONTENT:\n{'='*60}")
            print(s)
            return True
    return False


found = False

# 1. As-is
if try_decrypt("as-is", data):
    found = True

# 2. Skip first N
if not found:
    for skip in range(1, 16):
        if len(data) - skip < 16:
            break
        sub = data[skip:]
        if len(sub) % 16 != 0:
            continue
        if try_decrypt(f"skip_first_{skip}", sub):
            found = True
            break

# 3. Drop last N
if not found:
    for drop in range(1, 16):
        if len(data) - drop < 16:
            break
        sub = data[:len(data)-drop]
        if len(sub) % 16 != 0:
            continue
        if try_decrypt(f"drop_last_{drop}", sub):
            found = True
            break

# 4. Pad with zeros
if not found:
    pad_needed = (16 - len(data) % 16) % 16
    if pad_needed and len(data) >= 16:
        padded = data + b"\x00" * pad_needed
        if try_decrypt(f"pad_0x00_x{pad_needed}", padded):
            found = True

# 5. Pad with base64 spaces from end (common in base64 wrap)
if not found:
    pad_needed = (16 - len(data) % 16) % 16
    if pad_needed and len(data) >= pad_needed:
        padded = data + data[-pad_needed:]
        if try_decrypt(f"pad_tail_x{pad_needed}", padded):
            found = True

print()
if not found:
    print("=" * 60)
    print("✗ All attempts failed")
    print("=" * 60)
    print(f"Payload: {len(payload)} chars")
    if len(payload) % 4 == 0:
        print(f"Alignment: OK ({len(data)} bytes = {len(data)//16} blocks)")
        print("→ Alignment හරි — algorithm/key වැරදි වෙන්න පුළුවන්")
    else:
        print(f"Alignment: FAIL (payload % 4 = {len(payload) % 4})")
        print(f"→ {4 - len(payload) % 4} chars missing from link")
        print("→ Link එක නැවත copy කරන්න (app එකෙන් export කරන්න)")
    print()
    print("Diagnostic hex (for me to analyze):")
    print(f"  First 64 bytes: {data[:64].hex()}")
    print(f"  Last 32 bytes : {data[-32:].hex()}")
