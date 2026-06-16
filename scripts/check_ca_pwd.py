"""验证CA密钥密码"""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from pathlib import Path

BASE = Path(__file__).parent.parent / "pki_demo"

passwords = ['pki_demo_pwd', 'pki_demo_password', '123456', 'password']
for pwd in passwords:
    try:
        p = pwd.encode()
        with open(BASE / 'keys' / 'root_ca_private.pem', 'rb') as f:
            key = serialization.load_pem_private_key(f.read(), password=p, backend=default_backend())
        print(f'SUCCESS: password="{pwd}"')
        break
    except Exception as e:
        msg = str(e)
        if 'Bad decrypt' in msg or 'Incorrect password' in msg or 'Password' in msg:
            print(f'FAIL: "{pwd}"')
        else:
            print(f'ERROR: "{pwd}" -> {msg}')
else:
    print('ALL FAILED')
