"""
================================================================
  PKI Internal Program Access Control Module
  Verifies internal access certificate at startup
  Only authorized personnel with valid certificates can run the program
================================================================
"""

import os
import sys
import logging
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger("access_control")

# ============================================================
# Path Constants
# ============================================================
BASE_DIR = Path(__file__).parent.resolve()
CERTS_DIR = BASE_DIR / "certs"
KEYS_DIR = BASE_DIR / "keys"

# Internal access certificate path
# Distribution: place access_cert.pem in pki_demo/certs/
ACCESS_CERT_PATH = CERTS_DIR / "access_cert.pem"

# CA trust chain for verifying the access certificate issuer
TRUSTED_CA_CERTS = [
    CERTS_DIR / "root_ca_cert.pem",
    CERTS_DIR / "inter_ca_cert.pem",
]


def _load_certificate(cert_path):
    """Load a PEM-formatted certificate"""
    cert_path = Path(cert_path)
    if not cert_path.exists():
        return None, f"Certificate file not found: {cert_path}"
    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        return cert, None
    except Exception as e:
        return None, f"Failed to load certificate: {e}"


def _load_ca_chain():
    """Load CA trust chain certificates"""
    ca_certs = []
    errors = []
    for ca_path in TRUSTED_CA_CERTS:
        cert, err = _load_certificate(ca_path)
        if err:
            errors.append(err)
        else:
            ca_certs.append(cert)
    return ca_certs, errors


def verify_access_certificate(cert_path=None):
    """
    Verify the internal access certificate

    Validation rules:
    1. Certificate file must exist
    2. Certificate must be signed by a trusted CA (root or intermediate)
    3. Certificate must not be expired
    4. Certificate signature must be verifiable with CA public key

    Args:
        cert_path: Path to certificate file, defaults to ACCESS_CERT_PATH

    Returns:
        (is_valid: bool, message: str)
    """
    if cert_path is None:
        cert_path = ACCESS_CERT_PATH

    cert_path = Path(cert_path)

    # 1. Check certificate file exists
    if not cert_path.exists():
        return False, (
            f"[DENIED] Access certificate not found!\n"
            f"   expected: {cert_path}\n"
            f"   Please obtain access_cert.pem from the administrator.\n"
            f"   Or generate one: python scripts/gen_internal_access_cert.py"
        )

    # 2. Load access certificate
    access_cert, err = _load_certificate(cert_path)
    if err:
        return False, f"[DENIED] Access certificate is corrupted: {err}"

    # 3. Check certificate validity period
    now = datetime.now(timezone.utc)
    if now > access_cert.not_valid_after_utc:
        return False, (
            f"[DENIED] Access certificate has expired!\n"
            f"   Expired: {access_cert.not_valid_after_utc}\n"
            f"   Please contact administrator for a new certificate."
        )
    if now < access_cert.not_valid_before_utc:
        return False, (
            f"[DENIED] Access certificate is not yet valid!\n"
            f"   Valid from: {access_cert.not_valid_before_utc}"
        )

    # 4. Load CA trust chain
    ca_certs, ca_errors = _load_ca_chain()
    if not ca_certs:
        return False, (
            f"[FATAL] Cannot load CA trust chain, system integrity check failed!\n"
            f"   Details: {'; '.join(ca_errors)}"
        )

    # 5. Verify certificate chain
    issuer_cn = ""
    try:
        issuer_attrs = access_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        issuer_cn = issuer_attrs[0].value if issuer_attrs else ""
    except Exception:
        pass

    verified = False
    verify_errors = []
    for ca_cert in ca_certs:
        try:
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                access_cert.signature,
                access_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                access_cert.signature_hash_algorithm,
            )
            if access_cert.issuer != ca_cert.subject:
                verify_errors.append(
                    f"Issuer mismatch: certIssuer={issuer_cn}, "
                    f"CA Subject={ca_cert.subject}"
                )
                continue
            verified = True
            logger.info(
                f"Certificate verified, issuer CA: {issuer_cn}, "
                f"serial: {access_cert.serial_number}"
            )
            break
        except InvalidSignature:
            verify_errors.append(f"Signature verification failed (CA: {issuer_cn})")
            continue
        except Exception as e:
            verify_errors.append(f"Verification error: {e}")
            continue

    if not verified:
        return False, (
            f"[DENIED] Access certificate verification failed!\n"
            f"   Serial: {access_cert.serial_number}\n"
            f"   Issuer: {issuer_cn or 'Unknown'}\n"
            f"   Validity: {access_cert.not_valid_before_utc} ~ "
            f"{access_cert.not_valid_after_utc}\n"
            f"   Details: {'; '.join(verify_errors)}\n"
            f"   Please use a valid certificate distributed by the administrator."
        )

    return True, (
        f"[PASS] Access certificate verification successful\n"
        f"   Serial: {access_cert.serial_number}\n"
        f"   Expires: {access_cert.not_valid_after_utc}\n"
        f"   System startup authorized."
    )


def check_and_exit(cert_path=None):
    """
    Perform access control check, exit process if verification fails
    Call this function at the entry point of api_server.py
    """
    valid, msg = verify_access_certificate(cert_path)
    border = "=" * 60
    print(border)
    print("  PKI System - Internal Access Certificate Check")
    print(border)
    print()
    print(msg)
    print()
    if not valid:
        print(border)
        print("  [DENIED] Access rejected: certificate verification failed")
        print(border)
        sys.exit(1)
    else:
        print("  [PASS] Access authorized, starting service...")
        print(border)


# ============================================================
# Self-test
# ============================================================
if __name__ == "__main__":
    valid, msg = verify_access_certificate()
    print(msg)
    sys.exit(0 if valid else 1)
