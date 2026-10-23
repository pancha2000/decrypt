
#!/usr/bin/env python3
"""Step 1: recover original bytes from UTF-8-wrapped .hc file."""
import sys, re
from collections import Counter

XOR_KEY = bytes.fromhex("e382e4b8adc386f09f9293")

with open(sys.argv[1], 'rb') as f:
    raw = f.read()

text = raw.decode('utf-8')
cps = [ord(c) for c in text]

print(f"File: {len(raw)} bytes → {len(text)} UTF-8 chars")
print(f"Chars cp > 0xFF  : {sum(1 for c in cps if c > 0xFF)}")
print(f"Chars cp > 0xFFFF: {sum(1 for c in cps if c > 0xFFFF)}")

high = Counter(c for c in cps if c > 0xFF)
print(f"\nUnique codepoints > 0xFF: {len(high)}")
for cp, n in sorted(high.items())[:20]:
    print(f"  U+{cp:04X}: {n}×")

# --- Recovery methods ---
methods = {
    "mask &0xFF":    bytes(c & 0xFF for c in cps),
    "filter <0x100": bytes(c for c in cps if c <= 0xFF),
    "raw bytes":     raw,
}

print("\n" + "=" * 60)
for name, data in methods.items():
    if not data:
        continue
    xored = bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(data))
    try:
        s = xored.decode('ascii')
        is_hex = bool(re.fullmatch(r'[0-9a-fA-F]+', s)) and len(s) % 2 == 0
        status = f"HEX ✓ ({len(s)} chars)" if is_hex else f"ASCII but not hex"
    except UnicodeDecodeError:
        status = "non-ASCII"
    print(f"{name:15s} → {len(data):4d} bytes → XOR: {status}")
    print(f"                 first 20: {xored[:20].hex()}")
