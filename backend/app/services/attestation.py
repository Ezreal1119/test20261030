from __future__ import annotations

import hmac
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

UNVERIFIED = "Hardware-backed attestation not verified."
ATTESTATION_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
LEVELS = {0: "SOFTWARE", 1: "TRUSTED_ENVIRONMENT", 2: "STRONGBOX"}
ROOTS_PATH = Path(__file__).resolve().parent.parent / "resources" / "attestation_roots.pem"


def load_pinned_roots() -> list[x509.Certificate]:
    if not ROOTS_PATH.exists():
        return []
    data = ROOTS_PATH.read_bytes()
    if b"BEGIN CERTIFICATE" not in data:
        return []
    certs: list[x509.Certificate] = []
    for part in data.split(b"-----END CERTIFICATE-----"):
        if b"BEGIN CERTIFICATE" not in part:
            continue
        pem = part.strip() + b"\n-----END CERTIFICATE-----\n"
        certs.append(x509.load_pem_x509_certificate(pem))
    return certs


def verify_attestation(
    certificates: list[x509.Certificate],
    challenge: bytes,
    registered_spki: bytes,
    roots: list[x509.Certificate] | None = None,
) -> dict:
    pinned = load_pinned_roots() if roots is None else roots
    try:
        if len(certificates) < 2:
            return _fail("Certificate chain is too short to reach a trust anchor.")
        if not pinned:
            return _fail("No trusted attestation roots are configured.")
        _check_chain(certificates, pinned)
        leaf = certificates[0]
        _check_validity(leaf)
        leaf_spki = leaf.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if leaf_spki != registered_spki:
            return _fail("Attestation leaf public key does not match the registered key.")
        description = _extension_value(leaf)
        parsed = parse_key_description(description)
        if not hmac.compare_digest(parsed["challenge"], challenge):
            return _fail("Attestation challenge does not match the server challenge.")
        level_name = LEVELS.get(parsed["keymaster_security_level"], f"UNKNOWN({parsed['keymaster_security_level']})")
        if parsed["keymaster_security_level"] not in (1, 2):
            return _fail(f"Keymaster security level is {level_name}.")
        return {
            "verified": True,
            "status": f"Verified. Keymaster security level: {level_name}.",
            "security_level": level_name,
        }
    except (ValueError, InvalidSignature) as exc:
        return _fail(str(exc))


def parse_key_description(data: bytes) -> dict:
    tag, value, _ = _read_tlv(data, 0)
    if tag != 0x30:
        raise ValueError("Attestation extension is not a SEQUENCE")
    index = 0

    def take() -> tuple[int, bytes]:
        nonlocal index
        item_tag, item_value, index = _read_tlv(value, index)
        return item_tag, item_value

    version_tag, version = take()
    att_tag, att_level = take()
    km_version_tag, km_version = take()
    km_tag, km_level = take()
    challenge_tag, challenge = take()
    if (version_tag, att_tag, km_version_tag, km_tag, challenge_tag) != (0x02, 0x0A, 0x02, 0x0A, 0x04):
        raise ValueError("Attestation extension fields are not in the expected order")
    return {
        "attestation_version": int.from_bytes(version, "big"),
        "attestation_security_level": int.from_bytes(att_level, "big"),
        "keymaster_version": int.from_bytes(km_version, "big"),
        "keymaster_security_level": int.from_bytes(km_level, "big"),
        "challenge": challenge,
    }


def _check_chain(certificates: list[x509.Certificate], roots: list[x509.Certificate]) -> None:
    for index in range(len(certificates) - 1):
        certificates[index].verify_directly_issued_by(certificates[index + 1])
    last = certificates[-1]
    for root in roots:
        if last.public_bytes(serialization.Encoding.DER) == root.public_bytes(serialization.Encoding.DER):
            return
        try:
            last.verify_directly_issued_by(root)
            return
        except (ValueError, InvalidSignature):
            continue
    raise ValueError("Chain does not terminate at a pinned attestation root")


def _check_validity(certificate: x509.Certificate) -> None:
    now = datetime.now(timezone.utc)
    skew = timedelta(minutes=5)
    if now + skew < certificate.not_valid_before_utc or now - skew > certificate.not_valid_after_utc:
        raise ValueError("Attestation certificate is outside its validity period")


def _extension_value(certificate: x509.Certificate) -> bytes:
    try:
        extension = certificate.extensions.get_extension_for_oid(ATTESTATION_OID)
    except x509.ExtensionNotFound as exc:
        raise ValueError("Leaf certificate has no key attestation extension") from exc
    value = extension.value
    raw = getattr(value, "value", None)
    if not isinstance(raw, bytes):
        raise ValueError("Attestation extension could not be read")
    return raw


def _read_tlv(data: bytes, index: int) -> tuple[int, bytes, int]:
    if index >= len(data):
        raise ValueError("Truncated DER")
    tag = data[index]
    index += 1
    if index >= len(data):
        raise ValueError("Truncated DER length")
    length_byte = data[index]
    index += 1
    if length_byte < 0x80:
        length = length_byte
    else:
        count = length_byte & 0x7F
        if count == 0 or index + count > len(data):
            raise ValueError("Invalid DER length")
        length = int.from_bytes(data[index : index + count], "big")
        index += count
    if index + length > len(data):
        raise ValueError("Truncated DER value")
    return tag, data[index : index + length], index + length


def _fail(reason: str) -> dict:
    return {"verified": False, "status": f"{UNVERIFIED} {reason}", "security_level": None}


def build_key_description(challenge: bytes, attestation_level: int, keymaster_level: int) -> bytes:
    """Small DER writer used by tests and by nothing on the device path."""
    body = b"".join(
        [
            _der(0x02, _int_bytes(4)),
            _der(0x0A, bytes([attestation_level])),
            _der(0x02, _int_bytes(400)),
            _der(0x0A, bytes([keymaster_level])),
            _der(0x04, challenge),
            _der(0x04, b""),
            _der(0x30, b""),
            _der(0x30, b""),
        ]
    )
    return _der(0x30, body)


def _int_bytes(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 8) // 8, "big") if value else b"\x00"
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return raw


def _der(tag: int, value: bytes) -> bytes:
    length = len(value)
    if length < 0x80:
        encoded = bytes([length])
    else:
        raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
        encoded = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + encoded + value


def spki(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
