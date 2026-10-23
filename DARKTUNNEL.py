"""DARKTUNNEL decryptor — final production version."""
import json
import base64
import re
import contextlib
from typing import Optional, Any, Union
from Crypto.Cipher import AES

try:
    import msgpack
    MSGPACK_AVAILABLE = True
except ImportError:
    MSGPACK_AVAILABLE = False


class DTConstants:
    """Cryptographic artifacts and static keys for Dark Tunnel."""
    KEY_256: bytes = b"$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd"
    KEY_192: bytes = b"F)J@NcRfUjXn2r4u7x!A%D*G"
    IV: bytes = bytes.fromhex("232e39185523184a5723586242200e05")


# msgpack map markers (map8 / map16 / map32)
_MSGPACK_MAP = frozenset(range(0x80, 0x90)) | {0xde, 0xdf}


def _looks_like_msgpack(data: bytes) -> bool:
    return bool(data) and data[0] in _MSGPACK_MAP


class DTDecryptor:
    """Core decryption and parsing engine for Dark Tunnel configs."""

    @staticmethod
    def _base64_decode_safe(data: str) -> bytes:
        clean = data.replace("-", "+").replace("_", "/")
        clean += "=" * (-len(clean) % 4)
        return base64.b64decode(clean)

    @staticmethod
    def _aes_cfb_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Primary: AES-CFB-128 (Go's cipher.NewCFBDecrypter).
        Fallbacks: CFB-8, CBC, OFB, CTR — only if the primary result
        doesn't look like a msgpack map.
        """
        pt = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(data)
        if _looks_like_msgpack(pt):
            return pt
        for fn in (
            lambda: AES.new(key, AES.MODE_CFB, iv=iv, segment_size=8).decrypt(data),
            lambda: AES.new(key, AES.MODE_CBC, iv=iv).decrypt(data),
            lambda: AES.new(key, AES.MODE_OFB, iv=iv).decrypt(data),
            lambda: AES.new(key, AES.MODE_CTR, nonce=b"",
                            initial_value=int.from_bytes(iv[:8], "big")).decrypt(data),
        ):
            try:
                r = fn()
                if _looks_like_msgpack(r):
                    return r
            except Exception:
                continue
        return pt

    @staticmethod
    def _is_utf8_printable(value: bytes) -> bool:
        if not value:
            return False
        try:
            return bool(re.fullmatch(
                r"[^\x00-\x08\x0B\x0C\x0E-\x1F\x7F]*", value.decode("utf-8")
            ))
        except UnicodeDecodeError:
            return False

    @classmethod
    def _try_parse_json_string(cls, value: str) -> Union[dict, list, str]:
        stripped = value.strip()
        if (stripped.startswith("{") and stripped.endswith("}")) or \
           (stripped.startswith("[") and stripped.endswith("]")):
            with contextlib.suppress(Exception):
                fixed = re.sub(r'(:\s*)(\$[A-Za-z0-9_]+)', r'\1"\2"', stripped)
                return cls._normalize_for_json(json.loads(fixed))
        return value

    @classmethod
    def _normalize_for_json(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: cls._normalize_for_json(v)
                    for k, v in value.items()
                    if k.lower() != "password"}
        if isinstance(value, list):
            return [cls._normalize_for_json(v) for v in value]
        if isinstance(value, bytes):
            return (cls._try_parse_json_string(value.decode("utf-8"))
                    if cls._is_utf8_printable(value) else list(value))
        if isinstance(value, str):
            return cls._try_parse_json_string(value)
        return value

    @classmethod
    def _clean_encrypted(cls, value: Any, key: bytes, iv: bytes) -> Any:
        if isinstance(value, dict):
            cleaned = {}
            for k, v in value.items():
                if isinstance(k, str) and k.startswith("Encrypted") \
                        and isinstance(v, (bytes, bytearray)) and v:
                    try:
                        cleaned[k] = cls._aes_cfb_decrypt(bytes(v), key, iv)
                    except Exception:
                        cleaned[k] = v
                else:
                    cleaned[k] = cls._clean_encrypted(v, key, iv)
            return cleaned
        if isinstance(value, list):
            return [cls._clean_encrypted(v, key, iv) for v in value]
        return value

    @classmethod
    def execute(cls, file_bytes: bytes) -> Optional[str]:
        if not MSGPACK_AVAILABLE:
            print("[DT] msgpack not installed → pip install msgpack")
            return None

        try:
            raw_input = file_bytes.decode("utf-8", errors="ignore").strip()
            if not raw_input:
                return None
            if "://" in raw_input:
                raw_input = raw_input.split("://", 1)[1]

            outer = json.loads(cls._base64_decode_safe(raw_input).decode("utf-8"))
            if "encryptedLockedConfig" not in outer:
                return None

            enc = cls._base64_decode_safe(outer["encryptedLockedConfig"])
            decrypted_outer = cls._aes_cfb_decrypt(enc, DTConstants.KEY_256, DTConstants.IV)

            try:
                unpacked_outer = msgpack.unpackb(
                    decrypted_outer, raw=False, strict_map_key=False)
            except Exception as e:
                print(f"[DT] outer msgpack failed: {e}")
                return None

            if isinstance(unpacked_outer, dict) and \
                    "EncryptedLockedConfig" in unpacked_outer:
                inner_enc = unpacked_outer["EncryptedLockedConfig"]
                if isinstance(inner_enc, str):
                    inner_enc = inner_enc.encode("latin1")
                try:
                    decrypted_inner = cls._aes_cfb_decrypt(
                        inner_enc, DTConstants.KEY_192, DTConstants.IV)
                    unpacked_inner = msgpack.unpackb(
                        decrypted_inner, raw=False, strict_map_key=False)
                    unpacked_outer["EncryptedLockedConfig"] = cls._clean_encrypted(
                        unpacked_inner, DTConstants.KEY_192, DTConstants.IV)
                except Exception as e:
                    print(f"[DT] inner layer failed: {e}")

            outer["encryptedLockedConfig"] = unpacked_outer
            normalized = cls._normalize_for_json(outer)

            return (
                "HABIBI DARK TUNNEL SCRIPT\n"
                + "=" * 30 + "\n\n"
                + json.dumps(normalized, indent=4, ensure_ascii=False)
                + "\n\n" + "=" * 30 + "\ncode : @HABIBI_1ST"
            )
        except Exception as e:
            import traceback
            print(f"[DT] {type(e).__name__}: {e}")
            traceback.print_exc()
            return None


def run(file_bytes: bytes) -> Optional[str]:
    """Entry point for seamless integration."""
    return DTDecryptor.execute(file_bytes)
