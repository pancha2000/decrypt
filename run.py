#!/usr/bin/env python3
"""Runs all decryptor modules and reports which one succeeds."""
import sys
import requests

import HTTPCUSTOM
import HTTPINJECTOR
import DARKTUNNEL
import NETMOD
import NETMOD_LINK
import ZIVPN        # ← අලුතින් හදපු ZIVPN.py එක import වෙනවා

def decrypt_file(file_bytes: bytes):
    modules = [
        ("ZIVPN",        ZIVPN),        # ZIVPN එක මුලටම දාමු (safe)
        ("DARKTUNNEL",   DARKTUNNEL),
        ("NETMOD",       NETMOD),
        ("NETMOD_LINK",  NETMOD_LINK),
        ("HTTPCUSTOM",   HTTPCUSTOM),
        ("HTTPINJECTOR", HTTPINJECTOR),
    ]
    for name, mod in modules:
        print(f"\n{'=' * 60}\n[*] Trying {name}...\n{'=' * 60}")
        try:
            res = mod.run(file_bytes)
            if res:
                return name, res
            print(f"[*] {name}: returned None")
        except Exception as e:
            print(f"[*] {name} EXCEPTION: {type(e).__name__}: {e}")
    return None, None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run.py <url_or_filepath_or_link>")
        sys.exit(1)

    target = sys.argv[1].strip()
    file_bytes = None

    if target.lower().startswith("nm-") or target.lower().startswith("zivpn://"):
        print(f"[*] Detected link: {target[:40]}...")
        file_bytes = target.encode("utf-8")
    elif target.startswith(("http://", "https://")):
        print(f"[*] Downloading: {target}")
        try:
            r = requests.get(target, timeout=30)
            r.raise_for_status()
            file_bytes = r.content
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
