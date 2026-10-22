import sys
import requests
import contextlib

# සියලුම Decryptor Modules import කරගන්න
import HTTPCUSTOM
import HTTPINJECTOR
import DARKTUNNEL


def decrypt_file(file_bytes: bytes):
    """පිළිවෙලින් modules මඟින් decrypt කිරීමට උත්සාහ කරයි."""

    # 1. HTTPCUSTOM උත්සාහ කරන්න
    try:
        res = HTTPCUSTOM.run(file_bytes)
        if res:
            return "HTTPCUSTOM", res
    except Exception as e:
        print(f"[*] HTTPCUSTOM Error: {e}")

    # 2. HTTPINJECTOR උත්සාහ කරන්න
    try:
        res = HTTPINJECTOR.run(file_bytes)
        if res:
            return "HTTPINJECTOR", res
    except Exception as e:
        pass # අනවශ්‍ය නම් පෙන්වීම මඟ හැරිය හැක

    # 3. DARKTUNNEL උත්සාහ කරන්න
    try:
        res = DARKTUNNEL.run(file_bytes)
        if res:
            return "DARKTUNNEL", res
    except Exception as e:
        pass

    return None, None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run.py <url_or_filepath>")
        sys.exit(1)

    target = sys.argv[1]
    file_bytes = None

    # URL එකක්ද නැතහොත් Local File එකක්දැයි පරීක්ෂා කිරීම
    if target.startswith("http://") or target.startswith("https://"):
        print(f"[*] Downloading: {target}")
        resp = requests.get(target, timeout=30)
        if resp.status_code == 200:
            file_bytes = resp.content
        else:
            print("[-] Download failed")
            sys.exit(1)
    else:
        try:
            with open(target, "rb") as f:
                file_bytes = f.read()
        except Exception as e:
            print(f"[-] File reading error: {e}")
            sys.exit(1)

    module_name, result = decrypt_file(file_bytes)

    if result:
        print(f"[+] Decrypted Successfully using [{module_name}]!")
        print(result)
    else:
        print("[-] Decryption failed for all supported modules.")

