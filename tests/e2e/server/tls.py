"""TLS certificate generation and management for E2E testing."""

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_self_signed_cert(
    hostname: str,
    cert_path: Path,
    key_path: Path,
    ca_cert_path: Path | None = None,
    ca_key_path: Path | None = None,
) -> tuple[Path, Path]:
    """Generate self-signed certificate and private key.

    Args:
        hostname: Hostname for the certificate CN
        cert_path: Path to write certificate
        key_path: Path to write private key
        ca_cert_path: Optional path to write CA certificate
        ca_key_path: Optional path to write CA private key

    Returns:
        Tuple of (cert_path, key_path)
    """
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend(),
    )

    # Write private key
    with key_path.open("wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Generate certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Buckwild E2E Test"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Testing"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # Write certificate
    with cert_path.open("wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Generate CA certificate if requested (for mTLS)
    if ca_cert_path and ca_key_path:
        generate_ca_cert(ca_cert_path, ca_key_path)

    return (cert_path, key_path)


def generate_ca_cert(cert_path: Path, key_path: Path) -> tuple[Path, Path]:
    """Generate CA certificate for mTLS testing.

    Args:
        cert_path: Path to write CA certificate
        key_path: Path to write CA private key

    Returns:
        Tuple of (cert_path, key_path)
    """
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    # Generate private key for CA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend(),
    )

    # Write CA private key
    with key_path.open("wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Generate CA certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Buckwild Test CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Buckwild E2E Test"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Testing CA"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # Write CA certificate
    with cert_path.open("wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return (cert_path, key_path)


def ensure_certs_exist(hostname: str | None = None) -> dict[str, Path]:
    """Ensure certificates exist, generating if necessary.

    Args:
        hostname: Hostname for certificate (default: from environment or socket.gethostname())

    Returns:
        Dictionary with paths to server cert, key, CA cert, and CA key
    """
    if hostname is None:
        import socket

        hostname = os.environ.get("NODE_ID", socket.gethostname())

    certs_dir = Path("/certs")
    if not certs_dir.exists():
        certs_dir = Path.cwd() / "certs"

    server_cert = certs_dir / "server.crt"
    server_key = certs_dir / "server.key"
    ca_cert = certs_dir / "ca.crt"
    ca_key = certs_dir / "ca.key"

    # Generate if missing
    if not server_cert.exists() or not server_key.exists():
        generate_self_signed_cert(
            hostname=hostname,
            cert_path=server_cert,
            key_path=server_key,
            ca_cert_path=ca_cert,
            ca_key_path=ca_key,
        )

    return {
        "server_cert": server_cert,
        "server_key": server_key,
        "ca_cert": ca_cert,
        "ca_key": ca_key,
    }
