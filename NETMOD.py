"""NetMod .nm decryptor — AES-128-ECB."""
import json
import base64
import re
from typing import Optional, Any
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


class NetModConstants:
    """NetMod cryptographic constants."""
    KEY: bytes = b"<n3t5yn4^n3tm0d>"   # 16 bytes → AES-128-ECB


class NetModDecryptor:
    """Core decryption engine for NetMod .nm configs."""

    @staticmethod
    def _try_parse_inner_json(value: Any) -> Any:
        """Recursively unescape JSON-encoded strings (e.g. Alpn field)."""
        if isinstance(value, dict):
            return {k: NetModDecryptor._try_parse_inner_json(v) for k, v in value.items()}
        if isinstance(value, list):
            return [NetModDecryptor._try_parse_inner_json(v) for v in value]
        if isinstance(value, str):
            stripped = value.strip()
            if (stripped.startswith("{") and stripped.endswith("}")) or \
               (stripped.startswith("[") and stripped.endswith("]")):
                try:
                    return NetModDecryptor._try_parse_inner_json(json.loads(stripped))
                except Exception:
                    pass
        return value

    @classmethod
    def execute(cls, file_bytes: bytes) -> Optional[str]:
        try:
            # Step 1: text decode + strip whitespace
            text = file_bytes.decode("utf-8", errors="ignore")
            b64 = "".join(text.split())
            if not b64:
                return None

            # Step 2: base64 decode (URL-safe fallback)
            b64_clean = b64.replace("-", "+").replace("_", "/")
            b64_clean += "=" * (-len(b64_clean) % 4)
            try:
                data = base64.b64decode(b64_clean)
            except Exception as e:
                print(f"[NM] base64 decode failed: {e}")
                return None

            if len(data) % 16 != 0:
                print(f"[NM] not block-aligned ({len(data)} bytes)")
                return None

            # Step 3: AES-128-ECB decrypt
            cipher = AES.new(NetModConstants.KEY, AES.MODE_ECB)
            decrypted = cipher.decrypt(data)

            # Step 4: PKCS7 unpad (best-effort)
            try:
                decrypted = unpad(decrypted, AES.block_size)
            except Exception:
                # Not padded — trim trailing NULs
                decrypted = decrypted.rstrip(b"\x00")

            # Step 5: text decode
            plaintext = decrypted.decode("utf-8", errors="ignore").strip()
            if not plaintext:
                return None

            # Step 6: JSON parse (recursive inner-JSON unescape)
            if plaintext.startswith("{"):
                try:
                    obj = json.loads(plaintext)
                    obj = cls._try_parse_inner_json(obj)
                    body = json.dumps(obj, indent=4, ensure_ascii=False)
                except Exception as e:
                    print(f"[NM] JSON parse failed: {e}")
                    body = plaintext
            else:
                body = plaintext

            return (
                "HABIBI NETMOD SCRIPT\n"
                + "=" * 30 + "\n\n"
                + body
                + "\n\n" + "=" * 30 + "\ncode : @HABIBI_1ST"
            )
        except Exception as e:
            import traceback
            print(f"[NM] {type(e).__name__}: {e}")
            traceback.print_exc()
            return None


def run(file_bytes: bytes) -> Optional[str]:
    """Entry point for seamless integration."""
    return NetModDecryptor.execute(file_bytes)
