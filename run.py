#!/usr/bin/env python3
"""Runs all decryptor modules and reports which one succeeds."""
import sys
import requests

import HTTPCUSTOM
import HTTPINJECTOR
import DARKTUNNEL
import NETMOD


def decrypt_file(file_bytes: bytes):
    """Try each module in order. Return (name, output) or (None, None)."""
    modules = [
        ("HTTPCUSTOM",   HTTPCUSTOM),
        ("HTTPINJECTOR", HTTPINJECTOR),
        ("DARKTUNNEL",   DARKTUNNEL),
        ("NETMOD",       NETMOD),
    ]
    for name, mod in modules:
        print(f"\n{'=' * 60}\n[*] Trying {name}...\n{'=' * 60}")
        try:
            res = mod.run(file_bytes)
            if res:
                return name, res
            print(f"[*] {name}: returned None")
        except Exception as e:
            import traceback
            print(f"[*] {name} EXCEPTION: {type(e).__name__}: {e}")
            traceback.print_exc()
    return None, None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run.py <url_or_filepath>")
        sys.exit(1)

    target = sys.argv[1]
    file_bytes = None

    if target.startswith(("http://", "https://")):
        print(f"[*] Downloading: {target}")
        try:
            r = requests.get(target, timeout=30)
            r.raise_for_status()
            file_bytes = r.content
            print(f"[*] Downloaded {len(file_bytes)} bytes")
        except Exception as e:
            print(f"[-] Download failed: {e}")
            sys.exit(1)
    else:
        try:
            with open(target, "rb") as f:
                file_bytes = f.read()
            print(f"[*] Read {len(file_bytes)} bytes from {target}")
        except Exception as e:
            print(f"[-] File read error: {e}")
            sys.exit(1)

    name, result = decrypt_file(file_bytes)

    print("\n" + "=" * 60)
    if result:
        print(f"[+] Decrypted successfully with [{name}]")
        print("=" * 60)
        print(result)
    else:
        print("[-] Decryption failed for all supported modules.")
        print("=" * 60)
        print("Run: python debug_dt.py <file>  to diagnose")
