"""NetMod URI link decryptor — nm-vless://, nm-vmess://, nm-trojan://, nm-ss://, nm://
AES-128-ECB, key = b'<n3t5yn4^n3tm0d>', no IV, PKCS7 padding."""
import json
import base64
from typing import Optional
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


class NetModLinkConstants:
    KEY: bytes = b"<n3t5yn4^n3tm0d>"
    PREFIXES = (
        "nm-vless://", "nm-vmess://", "nm-trojan://",
        "nm-ss://", "nm-shadowsocks://", "nm://",
    )


class NetModLinkDecryptor:

    @staticmethod
    def _b64d(s: str) -> bytes:
        s = s.replace("-", "+").replace("_", "/")
        s += "=" * (-len(s) % 4)
        return base64.b64decode(s)

    @staticmethod
    def _looks_readable(b: bytes) -> bool:
        if not b or len(b) < 8:
            return False
        try:
            s = b.decode("utf-8")
            printable = sum(1 for c in s[:400] if c.isprintable() or c in "\n\r\t")
            return printable / min(len(s), 400) > 0.85
        except UnicodeDecodeError:
            return False

    @classmethod
    def _decrypt_ecb(cls, data: bytes) -> Optional[bytes]:
        """AES-128-ECB with alignment recovery (handles skip/pad for edge cases)."""
        attempts = []

        # 1) As-is (preferred)
        if len(data) % 16 == 0:
            attempts.append(("as-is", data))

        # 2) Skip first N bytes (header scenarios)
        for skip in range(1, 16):
            if len(data) - skip >= 16 and (len(data) - skip) % 16 == 0:
                attempts.append((f"skip{skip}", data[skip:]))

        # 3) Drop last N bytes
        for drop in range(1, 16):
            if len(data) - drop >= 16 and (len(data) - drop) % 16 == 0:
                attempts.append((f"drop{drop}", data[:len(data) - drop]))

        # 4) NUL-pad (partial link recovery)
        pad = (16 - len(data) % 16) % 16
        if pad and len(data) >= 16:
            attempts.append((f"pad{pad}", data + b"\x00" * pad))

        for label, ct in attempts:
            try:
                pt = AES.new(NetModLinkConstants.KEY, AES.MODE_ECB).decrypt(ct)
            except Exception:
                continue

            # Try PKCS7 unpad then NUL strip
            for suffix, cand in (("unpadded", None), ("nulstrip", pt.rstrip(b"\x00")), ("raw", pt)):
                if suffix == "unpadded":
                    try:
                        cand = unpad(pt, 16)
                    except Exception:
                        continue
                if cls._looks_readable(cand):
                    return cand
        return None

    @classmethod
    def execute(cls, file_bytes: bytes) -> Optional[str]:
        try:
            text = file_bytes.decode("utf-8", errors="ignore").strip()
            if not text:
                return None

            # Detect prefix
            prefix = None
            for p in NetModLinkConstants.PREFIXES:
                if text.lower().startswith(p.lower()):
                    prefix = p
                    break
            if not prefix:
                return None

            # Extract payload (strip query/fragment/whitespace)
            payload = text[len(prefix):].split("?")[0].split("#")[0].strip()
            if not payload:
                return None

            data = cls._b64d(payload)
            pt = cls._decrypt_ecb(data)
            if pt is None:
                print(f"[NM-LINK] decrypt failed ({len(data)} bytes)")
                return None

            out = pt.decode("utf-8", errors="ignore").strip()

            # Pretty-print JSON if applicable
            if out.startswith("{"):
                try:
                    obj = json.loads(out)
                    out = json.dumps(obj, indent=4, ensure_ascii=False)
                except Exception:
                    pass

            return (
                "HABIBI NETMOD LINK\n"
                + "=" * 30 + "\n"
                + f"Type  : {prefix.rstrip(':/')}\n"
                + f"Bytes : {len(data)} ({len(data) // 16} blocks)\n"
                + "=" * 30 + "\n\n"
                + out
                + "\n\n" + "=" * 30 + "\ncode : @HABIBI_1ST"
            )
        except Exception as e:
            import traceback
            print(f"[NM-LINK] {type(e).__name__}: {e}")
            traceback.print_exc()
            return None


def run(file_bytes: bytes) -> Optional[str]:
    return NetModLinkDecryptor.execute(file_bytes)
