import sys
import requests
from HTTPINJECTOR import run

if len(sys.argv) < 2:
    print("Usage: python decrypt_url.py <url>")
    sys.exit(1)

url = sys.argv[1]
print(f"[*] Downloading: {url}")
resp = requests.get(url, timeout=30)
if resp.status_code != 200:
    print("[-] Download failed")
    sys.exit(1)

result = run(resp.content)
if result:
    print("[+] Decrypted Successfully!")
    print(result)
else:
    print("[-] Decryption failed")
