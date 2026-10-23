
#!/usr/bin/env python3
"""Quick decoder for nm-*:// links."""
import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

LINK = """nm-vless://o47BCrVysu8Xq/jZhvZ/4mqqdJBgFSSIQW7unu6C8QgbEExXIXCU/GrKAHhTI4kie/vG0se08aDPQ7G9u5pbHRRw/JR4+hg0TKka8wN3LVsFJqaVz2gXhcIphLwrZTi77Fo7r38pDoVfpLSbOLvMrjfN5Qu6FAufs+T77LVHlwMERV79AghL9LpYUlkGWxjZuDNp/9YevWAdzC/RlS26cFtBQQgmhNVnc1+smBVIA+R2esH5V3yO2m3pBJTjwde"""

KEY = b"<n3t5yn4^n3tm0d>"

# Step 1: strip prefix
if "://" not in LINK:
    print("No scheme found")
    raise SystemExit(1)

scheme, payload = LINK.split("://", 1)
print(f"Scheme: {scheme}")
print(f"Payload length: {len(payload)} chars")

# Step 2: strip query/fragment
payload = payload.split("?")[0].split("#")[0].strip()

# Step 3: base64 decode
b64 = payload.replace("-", "+").replace("_", "/")
b64 += "=" * (-len(b64) % 4)
data = base64.b64decode(b64)
print(f"Decoded: {len(data)} bytes  (blocks: {len(data)//16})")

# Step 4: AES-128-ECB decrypt
pt = AES.new(KEY, AES.MODE_ECB).decrypt(data)
try:
    pt = unpad(pt, 16)
except Exception:
    pt = pt.rstrip(b"\x00")

text = pt.decode("utf-8", errors="replace")
print("\n=== Decrypted ===")
print(text)

# Step 5: try JSON pretty-print
if text.strip().startswith("{"):
    try:
        obj = json.loads(text)
        print("\n=== Pretty JSON ===")
        print(json.dumps(obj, indent=4, ensure_ascii=False))
    except Exception as e:
        print(f"(JSON parse failed: {e})")
