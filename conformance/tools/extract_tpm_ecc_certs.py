#!/usr/bin/env python3
"""
Pulls the leaf and batch (issuer) certificates out of a captured Resp-9 P-4 (TPM ECDSA
SECP256R1) attestation/result request, for reporting against
https://github.com/fido-alliance/conformance-test-tools-resources/issues/862.

Reads a conformance:trafficLog .jsonl file (see conformance/README.md), finds every
/attestation/result request whose attStmt is fmt="tpm" alg=-7 (ES256), decodes the x5c
chain, and:
  - writes each certificate as PEM (leaf and batch, per matching record)
  - prints the leaf's Authority Key Identifier extension (raw bytes) and the batch
    certificate's Subject Key Identifier, so a mismatch/double-wrap is visible directly
  - prints the record's own Outcome/ErrorCode/ErrorMessage, so it's clear whether this
    run actually reproduced the InvalidCertificateChain failure or not

Usage:
    python3 conformance/tools/extract_tpm_ecc_certs.py <run>.jsonl [--seq N] [--out-dir DIR]

--seq restricts to one record by its Sequence number (use this if more than one TPM
ES256 request appears in the log and you want a specific one). Default: process all
matches.
"""

import argparse
import base64
import json
import sys
from pathlib import Path

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID


def b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def find_tpm_ecc_records(lines, only_seq):
    for line in lines:
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)

        if record.get("Path") != "/attestation/result":
            continue
        if only_seq is not None and record.get("Sequence") != only_seq:
            continue

        request = record.get("Request")
        if not isinstance(request, dict):
            continue

        response = request.get("response") or request.get("Response")
        if not isinstance(response, dict):
            continue

        att_obj_b64 = response.get("attestationObject") or response.get("AttestationObject")
        if not att_obj_b64:
            continue

        try:
            att_obj = cbor2.loads(b64url_decode(att_obj_b64))
        except Exception:
            continue

        if not isinstance(att_obj, dict) or att_obj.get("fmt") != "tpm":
            continue

        att_stmt = att_obj.get("attStmt", {})
        if not isinstance(att_stmt, dict) or att_stmt.get("alg") != -7:  # ES256
            continue

        yield record, att_stmt


def describe_extension(cert: x509.Certificate, oid, label: str):
    try:
        ext = cert.extensions.get_extension_for_oid(oid)
    except x509.ExtensionNotFound:
        print(f"    {label}: <not present>")
        return
    raw = ext.value.public_bytes() if hasattr(ext.value, "public_bytes") else None
    print(f"    {label} (critical={ext.critical}): {ext.value}")
    if raw is not None:
        print(f"      DER: {raw.hex()}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("log", type=Path, help="conformance:trafficLog .jsonl file")
    parser.add_argument("--seq", type=int, default=None, help="restrict to one record by Sequence number")
    parser.add_argument("--out-dir", type=Path, default=Path("."), help="where to write the .pem files (default: cwd)")
    args = parser.parse_args()

    lines = args.log.read_text(encoding="utf-8").splitlines()
    matches = list(find_tpm_ecc_records(lines, args.seq))

    if not matches:
        print("No TPM ES256 (fmt=tpm, alg=-7) attestation/result request found in this log.", file=sys.stderr)
        if args.seq is not None:
            print(f"(filtered to --seq {args.seq})", file=sys.stderr)
        sys.exit(1)

    args.out_dir.mkdir(parents=True, exist_ok=True)

    for record, att_stmt in matches:
        seq = record.get("Sequence")
        outcome = record.get("Outcome")
        code = record.get("ErrorCode")
        message = record.get("ErrorMessage")

        print(f"=== seq {seq} ===")
        print(f"  Outcome: {outcome}  Code: {code}")
        print(f"  Message: {message}")

        x5c = att_stmt.get("x5c") or []
        if len(x5c) < 2:
            print(f"  x5c has {len(x5c)} certificate(s); expected at least leaf + batch. Skipping.")
            continue

        certs = [x509.load_der_x509_certificate(bytes(der)) for der in x5c]
        leaf, batch = certs[0], certs[1]

        leaf_path = args.out_dir / f"leaf-seq{seq}.pem"
        batch_path = args.out_dir / f"batch-seq{seq}.pem"
        leaf_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        batch_path.write_bytes(batch.public_bytes(serialization.Encoding.PEM))
        print(f"  wrote {leaf_path}")
        print(f"  wrote {batch_path}")

        print("  --- leaf ---")
        print(f"    Subject: {leaf.subject.rfc4514_string()}")
        print(f"    Issuer:  {leaf.issuer.rfc4514_string()}")
        describe_extension(leaf, ExtensionOID.AUTHORITY_KEY_IDENTIFIER, "AuthorityKeyIdentifier")

        print("  --- batch (issuer) ---")
        print(f"    Subject: {batch.subject.rfc4514_string()}")
        describe_extension(batch, ExtensionOID.SUBJECT_KEY_IDENTIFIER, "SubjectKeyIdentifier")
        print()


if __name__ == "__main__":
    main()
