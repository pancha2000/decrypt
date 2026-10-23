"""ZiVPN .ziv decryptor — PBKDF2-HMAC-SHA256 + AES-128-GCM."""
import base64
import hashlib
import json
from typing import Optional
from Crypto.Cipher import AES
from xml.dom import minidom

class ZIVPNConstants:
    # SecurePart1 + SecurePart2 + SecurePart3 + SecurePart4 + SecurePart5
    PASSPHRASE: bytes = b"SecurePart1SecurePart2SecurePart3SecurePart4SecurePart5"
    ITERATIONS: int = 1000
    KEY_LEN: int = 16


class ZIVPNDecryptor:

    @staticmethod
    def _b64d(data: str) -> bytes:
        """Handle standard and URL-safe base64."""
        data = data.replace("-", "+").replace("_", "/")
        data += "=" * (-len(data) % 4)
        return base64.b64decode(data)

    @classmethod
    def execute(cls, file_bytes: bytes) -> Optional[str]:
        try:
            # 1. Read text and strip whitespace
            text = file_bytes.decode("utf-8", errors="ignore").strip()
            if not text or "." not in text:
                return None

            # 2. Split by '.' -> salt.iv.ciphertext
            parts = text.split(".")
            if len(parts) != 3:
                return None
                
            salt_b64, iv_b64, ct_b64 = parts

            # 3. Base64 decode
            salt = cls._b64d(salt_b64)
            iv = cls._b64d(iv_b64)
            ct_tag = cls._b64d(ct_b64)

            if len(iv) != 12:
                print(f"[ZIV] Warning: IV length is {len(iv)}, expected 12 for GCM")
            if len(ct_tag) <= 16:
                print("[ZIV] Error: ciphertext too short (no room for GCM tag)")
                return None

            # 4. Derive Key via PBKDF2
            key = hashlib.pbkdf2_hmac(
                'sha256',
                ZIVPNConstants.PASSPHRASE,
                salt,
                ZIVPNConstants.ITERATIONS,
                dklen=ZIVPNConstants.KEY_LEN
            )

            # 5. Decrypt AES-GCM
            ciphertext = ct_tag[:-16]
            tag = ct_tag[-16:]

            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            try:
                decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            except ValueError as e:
                print(f"[ZIV] AES-GCM Auth failed (wrong key or corrupted file): {e}")
                return None

            # 6. Format Output (XML or JSON)
            plaintext = decrypted.decode("utf-8", errors="ignore").strip()
            if not plaintext:
                return None

            # Check if it's XML and pretty-print it
            if plaintext.startswith("<"):
                try:
                    xml_dom = minidom.parseString(plaintext)
                    body = xml_dom.toprettyxml(indent="  ")
                    # Remove empty lines from minidom
                    body = "\n".join([line for line in body.split("\n") if line.strip()])
                except Exception:
                    body = plaintext
            # Check if it's JSON
            elif plaintext.startswith("{"):
                try:
                    body = json.dumps(json.loads(plaintext), indent=4, ensure_ascii=False)
                except Exception:
                    body = plaintext
            else:
                body = plaintext

            return (
                "HABIBI ZIVPN SCRIPT\n"
                + "=" * 30 + "\n\n"
                + body
                + "\n\n" + "=" * 30 + "\ncode : @HABIBI_1ST"
            )

        except Exception as e:
            import traceback
            print(f"[ZIV] {type(e).__name__}: {e}")
            traceback.print_exc()
            return None


def run(file_bytes: bytes) -> Optional[str]:
    """Entry point for seamless integration."""
    return ZIVPNDecryptor.execute(file_bytes)
