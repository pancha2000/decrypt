"""DARKTUNNEL decryptor — fixed version with auto AES mode detection."""
import json
import base64
import re
import contextlib
from typing import Optional, Any, Union, List
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


# msgpack map markers (map8/map16/map32)
_MSGPACK_MAP_MARKERS = frozenset(range(0x80, 0x90)) | {0xde, 0xdf}


def _looks_like_msgpack(data: bytes) -> bool:
    return bool(data) and data[0] in _MSGPACK_MAP_MARKERS


class DTDecryptor:
    """Core decryption and parsing engine for Dark Tunnel configs."""

    @staticmethod
    def _base64_decode_safe(data: str) -> bytes:
        clean_data = data.replace("-", "+").replace("_", "/")
        if pad := len(clean_data) % 4:
            clean_data += "=" * (4 - pad)
        return base64.b64decode(clean_data)

    @staticmethod
    def _aes_cfb_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Auto-detect CFB segment size:
          - Go's cipher.NewCFBDecrypter → CFB-128
          - Java/Android Cipher CFB → often CFB-8
        Returns the first result that looks like a msgpack map.
        Falls back to CFB-128 if neither matches.
        """
        pt128 = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(data)
        if _looks_like_msgpack(pt128):
            return pt128
        try:
            pt8 = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=8).decrypt(data)
            if _looks_like_msgpack(pt8):
                return pt8
        except Exception:
            pass
        # Fallback: try CBC / OFB / CTR (rarely needed)
        for mode, fn in [
            (AES.MODE_CBC, lambda: AES.new(key, AES.MODE_CBC, iv=iv).decrypt(data)),
            (AES.MODE_OFB, lambda: AES.new(key, AES.MODE_OFB, iv=iv).decrypt(data)),
            (AES.MODE_CTR, lambda: AES.new(
                key, AES.MODE_CTR, nonce=b"",
                initial_value=int.from_bytes(iv[:8], "big"),
            ).decrypt(data)),
        ]:
            try:
                pt = fn()
                if _looks_like_msgpack(pt):
                    return pt
            except Exception:
                continue
        return pt128  # original behavior as last resort

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
                fixed_json = re.sub(r'(:\s*)(\$[A-Za-z0-9_]+)', r'\1"\2"', stripped)
                return cls._normalize_for_json(json.loads(fixed_json))
        return value

    @classmethod
    def _normalize_for_json(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: cls._normalize_for_json(v)
                    for k, v in value.items() if k != "Password"}
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
                        and v and isinstance(v, (bytes, bytearray)):
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
            return None

        try:  # ← explicit try/except so errors are printed, not silent
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
                unpacked_outer = msgpack.unpackb(decrypted_outer, raw=False,
                                                 strict_map_key=False)
            except Exception as e:
                print(f"[DT] outer msgpack failed: {e}")
                return None

            if isinstance(unpacked_outer, dict) and \
                    "EncryptedLockedConfig" in unpacked_outer:
                inner_enc = unpacked_outer["EncryptedLockedConfig"]
                if isinstance(inner_enc, str):
                    inner_enc = inner_enc.encode("latin1")
                decrypted_inner = cls._aes_cfb_decrypt(
                    inner_enc, DTConstants.KEY_192, DTConstants.IV)
                try:
                    unpacked_inner = msgpack.unpackb(decrypted_inner, raw=False,
                                                     strict_map_key=False)
                    unpacked_outer["EncryptedLockedConfig"] = cls._clean_encrypted(
                        unpacked_inner, DTConstants.KEY_192, DTConstants.IV)
                except Exception as e:
                    print(f"[DT] inner msgpack failed: {e}")

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
            print(f"[DT] EXCEPTION: {type(e).__name__}: {e}")
            traceback.print_exc()
            return None


def run(file_bytes: bytes) -> Optional[str]:
    """Entry point for seamless integration."""
    return DTDecryptor.execute(file_bytes)
