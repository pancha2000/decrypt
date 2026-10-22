import sys
import requests
import traceback
import base64
import json

import HTTPCUSTOM
import HTTPINJECTOR
import DARKTUNNEL


def inspect_input(file_bytes: bytes):
    """මූලික format එක බලන්න"""
    print("\n" + "=" * 70)
    print("[INPUT INSPECTION]")
    print("=" * 70)
    print(f"  Size: {len(file_bytes)} bytes")
    print(f"  First 20 bytes (hex): {file_bytes[:20].hex()}")
    print(f"  First 80 bytes (repr): {file_bytes[:80]!r}")
    
    # Text decode?
    try:
        text = file_bytes.decode("utf-8")
        print(f"  ✓ Valid UTF-8. Length: {len(text)}")
        stripped = text.strip()
        print(f"  First 80 chars: {stripped[:80]!r}")
        
        # Strip scheme
        if "://" in stripped:
            scheme = stripped.split("://", 1)[0]
            rest = stripped.split("://", 1)[1]
            print(f"  ✓ Has scheme: '{scheme}://'")
            print(f"  After scheme: {rest[:80]!r}")
            stripped = rest
        else:
            print(f"  ✗ No scheme found")
        
        # Base64 decode?
        try:
            clean = stripped.replace("-", "+").replace("_", "/")
            clean += "=" * (-len(clean) % 4)
            decoded = base64.b64decode(clean, validate=False)
            print(f"  ✓ Base64 decode OK: {len(decoded)} bytes")
            print(f"    First 20 hex: {decoded[:20].hex()}")
            print(f"    First 80 repr: {decoded[:80]!r}")
            
            # JSON?
            try:
                obj = json.loads(decoded.decode("utf-8"))
                print(f"  ✓ JSON parse OK. Type: {type(obj).__name__}")
                if isinstance(obj, dict):
                    print(f"    Keys: {list(obj.keys())}")
                # Check for known formats
                if isinstance(obj, dict):
                    for field in ["encryptedLockedConfig", "encryptedConfig", 
                                  "config", "payload", "data", "settings"]:
                        if field in obj:
                            print(f"    ✓ Has field: '{field}'")
                return "JSON_BASE64"
            except Exception as e:
                print(f"  ✗ JSON parse FAILED: {e}")
                print(f"    Decoded text preview: {decoded[:200]!r}")
                return "BINARY_BASE64"
        except Exception as e:
            print(f"  ✗ Base64 decode FAILED: {e}")
            return "TEXT_NOT_BASE64"
    except UnicodeDecodeError:
        print(f"  ✗ Not valid UTF-8 — binary file")
        return "RAW_BINARY"


def try_module(name, module, file_bytes):
    print(f"\n" + "=" * 70)
    print(f"[TRYING: {name}]")
    print("=" * 70)
    try:
        res = module.run(file_bytes)
        if res:
            print(f"  ✓ SUCCESS! Output length: {len(res)}")
            return res
        else:
            print(f"  ✗ Returned None (silent fail)")
            return None
    except Exception as e:
        print(f"  ✗ Exception: {type(e).__name__}: {e}")
        traceback.print_exc()
        return None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run_debug.py <url_or_filepath>")
        sys.exit(1)
    
    target = sys.argv[1]
    file_bytes = None
    
    if target.startswith("http://") or target.startswith("https://"):
        print(f"[*] Downloading: {target}")
        try:
            resp = requests.get(target, timeout=30)
            print(f"[*] HTTP {resp.status_code}, {len(resp.content)} bytes")
            if resp.status_code == 200:
                file_bytes = resp.content
            else:
                print(f"[-] Download failed: HTTP {resp.status_code}")
                sys.exit(1)
        except Exception as e:
            print(f"[-] Download error: {e}")
            sys.exit(1)
    else:
        try:
            with open(target, "rb") as f:
                file_bytes = f.read()
            print(f"[*] Read {len(file_bytes)} bytes from {target}")
        except Exception as e:
            print(f"[-] File read error: {e}")
            sys.exit(1)
    
    fmt = inspect_input(file_bytes)
    print(f"\n[*] Detected input format: {fmt}")
    
    modules = [
        ("HTTPCUSTOM", HTTPCUSTOM),
        ("HTTPINJECTOR", HTTPINJECTOR),
        ("DARKTUNNEL", DARKTUNNEL),
    ]
    
    for name, mod in modules:
        result = try_module(name, mod, file_bytes)
        if result:
            print(f"\n{'='*70}")
            print(f"[✓] DECRYPTED BY: {name}")
            print('='*70)
            print(result)
            break
    else:
        print(f"\n{'='*70}")
        print("[-] All modules failed. Input format may not be supported.")
        print('='*70)
