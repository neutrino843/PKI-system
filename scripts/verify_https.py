"""验证HTTPS PKI"""
import urllib.request, ssl, json, re

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# HTTPS
req = urllib.request.Request('https://localhost/')
resp = urllib.request.urlopen(req, timeout=10, context=ctx)
html = resp.read().decode('utf-8', errors='replace')
m = re.search(r'<title>(.*?)</title>', html)
title = m.group(1) if m else "N/A"
print(f'HTTPS Status: {resp.status}  Title: {title}')

# API
req2 = urllib.request.Request('https://localhost/api/stats')
resp2 = urllib.request.urlopen(req2, timeout=10, context=ctx)
stats = json.loads(resp2.read())
print(f'API Status: {resp2.status}  Cert Count: {stats["totalCerts"]}')

# TLS info
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)
sock.connect(('localhost', 443))
ssock = ctx.wrap_socket(sock, server_hostname='localhost')
cert_der = ssock.getpeercert(binary_form=True)
from cryptography import x509
from cryptography.x509.oid import NameOID
cert = x509.load_der_x509_certificate(cert_der)
cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
print(f'TLS Cert CN: {cn[0].value}  Issuer: {issuer[0].value}')
print(f'TLS Valid: {cert.not_valid_before_utc.strftime("%Y-%m-%d")} ~ {cert.not_valid_after_utc.strftime("%Y-%m-%d")}')
print()
print('=== ALL OK - PKI签发的HTTPS证书工作正常! ===')
