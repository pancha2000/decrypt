import sys
import json
import base64
import re
import traceback
from typing import Optional, Dict, Any, List
from Crypto.Cipher import ChaCha20, AES
from Crypto.Util.Padding import unpad


class HCConstants:
    CHACHA_KEYS: List[bytes] = [
        bytes.fromhex("2be4342943c6f91ff58987f41a1aafd179eeb4e053f5cea55b11d6a7db58bd7d"),
        bytes.fromhex("3380aa278b744ba5b529a7f32fa803e48749280dae378345d9b526cf1dbce372"),
        bytes.fromhex("cea9305c95168b162a335b137c61983b8df54e6375da01136547890f14c5fac3"),
        bytes.fromhex("4beeace0e42bae8f29470cf40cf2dfacd5f4e1f751912bf52e803c8c85792193"),
        bytes.fromhex("f8e5f6ebea90558eb32229da24fd0fb7d813091dafe89bb2954fda33b4c60f63"),
        bytes.fromhex("81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c"),
        bytes.fromhex("45635e6fc70486e2fd10d3c2b4780f02d0b4c5f4aa929fc54f86bb8fa4417944"),
        bytes.fromhex("3d632a251c9820f2baf83e15498d27548fc67921cb437f8ce48505989378adea")
    ]
    
    RST_KEYS: List[bytes] = [
        b"JN1k3YHc2.6_v235", b"JN1k3YHc_2.7_v71", b"JN1k3YHc2.7.ps69",
        b"JN1k3YHc2.7.6950", b"Jn1K3yHc2.8.ps08", b"Jn1K3yHc2.9.ps6c",
        b"Zk:L7>WKaiK*s9>D", b"!<f!&WIlM**R.B0X", b"b4a5opinx2uloec6"
    ]

    STATIC_NONCE: bytes = b'\xdb' * 8


def clean_hex(raw_str: str) -> str:
    clean = re.sub(r'[^0-9a-fA-F]', '', raw_str or "")
    return f"0{clean}" if len(clean) % 2 != 0 else clean


def abc_decrypt(raw_input: str, key: bytes, nonce: bytes = HCConstants.STATIC_NONCE) -> str:
    try:
        data = bytes.fromhex(clean_hex(raw_input))
        if len(data) > 16:
            cipher = ChaCha20.new(key=key, nonce=nonce)
            cipher.seek(64)
            return cipher.decrypt(data[:-16]).decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[DEBUG] abc_decrypt exception: {e}")
    return ""


def extract_initial_payload(file_bytes: bytes, hex_key: str) -> Optional[str]:
    try:
        key_bytes = bytes.fromhex(hex_key)
        k_len = len(key_bytes)
        try:
            encrypted_data = file_bytes.decode('utf-8', errors='ignore').encode('latin-1', errors='ignore')
        except Exception:
            encrypted_data = file_bytes 
        return bytes(b ^ key_bytes[i % k_len] for i, b in enumerate(encrypted_data)).decode('utf-8')
    except Exception as e:
        print(f"[DEBUG] Initial XOR extraction failed: {e}")
        return None


def debug_file(filepath: str):
    print(f"[*] Testing File: {filepath}")
    
    with open(filepath, 'rb') as f:
        file_bytes = f.read()

    print(f"[*] File Size: {len(file_bytes)} bytes")
    
    # Step 1: Initial payload extraction
    hex_payload = extract_initial_payload(file_bytes, "e382e4b8adc386f09f9293")
    if not hex_payload:
        print("[-] Step 1 Failed: Initial XOR payload extraction returned None")
        return
    print(f"[+] Step 1 Passed: Payload extracted (Length: {len(hex_payload)})")

    # Step 2: Outer ABC Decryption
    outer = abc_decrypt(hex_payload, HCConstants.CHACHA_KEYS[5])
    if not outer:
        print("[-] Step 2 Failed: Outer ChaCha20 decryption (Key 5) failed")
        return
    if not outer.startswith("{"):
        print(f"[-] Step 2 Failed: Decrypted outer is not valid JSON text. Starts with: {outer[:30]!r}")
        return
    print("[+] Step 2 Passed: Outer JSON payload decrypted successfully")

    # Step 3: Parse Outer JSON
    try:
        json_obj = json.loads(outer)
        print(f"[+] Step 3 Passed: Outer JSON parsed. Keys: {list(json_obj.keys())}")
    except Exception as e:
        print(f"[-] Step 3 Failed: Outer JSON parsing failed: {e}")
        return

    # Step 4: Check Inner Configuration
    cfg_obj = json_obj.get("cfg", {})
    is_new_format = isinstance(cfg_obj, dict) and "content" in cfg_obj
    print(f"[*] Format: {'New Format (v2.x+)' if is_new_format else 'Old Format'}")

    target_cipher = cfg_obj.get('content') if is_new_format else (json_obj.get('xy') or (json_obj.get('a') or {}).get('xy'))
    split_delim = "[splitConfig]" if is_new_format else (json_obj.get('uv') or (json_obj.get('a') or {}).get('uv'))

    print(f"[*] Target Cipher Present: {bool(target_cipher)}")
    print(f"[*] Split Delimiter: {split_delim!r}")

    if not target_cipher:
        print("[-] Step 4 Failed: Target cipher (xy / content) not found in JSON")
        return


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 debug_hc.py <file.hc>")
        sys.exit(1)
    debug_file(sys.argv[1])

