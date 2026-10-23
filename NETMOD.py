"""NetMod .nm decryptor — AES-128-ECB."""
import json
import base64
from typing import Optional, Any
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

class NetModConstants:
    KEY: bytes = b"<n3t5yn4^n3tm0d>"

class NetModDecryptor:
    @staticmethod
    def _try_parse_inner_json(value: Any) -> Any:
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
            text = file_bytes.decode("utf-8", errors="ignore").strip()
            if not text or "." in text:  # .ziv file එකක් නම් මෙතනින්ම අත්හරිනවා
                return None

            b64 = "".join(text.split())
            b64_clean = b64.replace("-", "+").replace("_", "/")
            b64_clean += "=" * (-len(b64_clean) % 4)
            
            try:
                data = base64.b64decode(b64_clean)
            except Exception:
                return None

            if len(data) % 16 != 0 or len(data) < 16:
                return None

            cipher = AES.new(NetModConstants.KEY, AES.MODE_ECB)
            decrypted = cipher.decrypt(data)

            try:
                decrypted = unpad(decrypted, AES.block_size)
            except Exception:
                decrypted = decrypted.rstrip(b"\x00")

            plaintext = decrypted.decode("utf-8", errors="ignore").strip()
            
            # JSON එකක් නෙවෙයි නම්, මේක .nm file එකක් නෙවෙයි! ඒ නිසා None return කරන්න.
            if not plaintext.startswith("{"):
                return None

            try:
                obj = json.loads(plaintext)
                obj = cls._try_parse_inner_json(obj)
                body = json.dumps(obj, indent=4, ensure_ascii=False)
            except Exception:
                return None # JSON error එකක් ආවොත් None

            return (
                "HABIBI NETMOD SCRIPT\n"
                + "=" * 30 + "\n\n"
                + body
                + "\n\n" + "=" * 30 + "\ncode : @HABIBI_1ST"
            )
        except Exception:
            return None

def run(file_bytes: bytes) -> Optional[str]:
    return NetModDecryptor.execute(file_bytes)
