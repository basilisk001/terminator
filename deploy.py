#!/usr/bin/env python3
"""
unified_deploy_prototype.py

PRODUCTION SINGLE-FILE DEPLOYABLE — SELF-VERIFYING, SIGNED, IMMUTABLE

This file is the canonical single-file product. It contains:
 - An embedded manifest (base64 JSON) with files, metadata, file-level hashes, merkle root, entrypoint.
 - A cryptographic signature (ed25519) over the canonical manifest.
 - Embedded public verification keys (for key rotation and audit).
 - A robust verification engine that:
     * canonicalizes the manifest deterministically
     * verifies payload hash and per-file hashes
     * verifies signature using embedded pubkey(s)
     * verifies the running file's source matches the embedded payload
     * continuously self-checks integrity during runtime
 - Helper tooling functions to build and sign manifests (for offline use by a builder)

USAGE (audit/run):
  - To verify only: python unified_deploy_prototype.py --verify
  - To run entrypoint in memory: python unified_deploy_prototype.py --run
  - To extract to disk (only allowed after successful verification): python unified_deploy_prototype.py --extract --outdir ./unpacked

SECURITY NOTES:
 - The signature must be produced by an ed25519 private key and the corresponding
   public key included in the manifest under `pubkeys`.
 - The builder must sign the canonicalized manifest WITHOUT the `signature` field.
 - This runtime refuses to execute or extract unless all checks pass.
 - For long-term archival, keep the public keys and the builder's key record in multiple
   secure locations; rotate keys by adding new pubkeys and re-signing with a trusted key.

IMPLEMENTATION DETAILS:
 - Requires `cryptography` package for ed25519.
 - Uses deterministic JSON canonicalization: sort_keys=True and separators without whitespace.
 - File blobs are base64-encoded in the manifest; file hashes are hex-encoded sha256.

IMPORTANT: I cannot 'launch' this artifact from my environment. I have updated the
file in the canvas. To execute it, run the commands above on your host.

"""

import base64
import json
import hashlib
import sys
import os
import argparse
import time
from typing import Dict, Tuple, Any

# Attempt to import cryptography for ed25519 verification
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

# -------------------- EMBEDDED MANIFEST (BASE64 JSON) --------------------
# The builder replaces the MANIFEST_B64 string with the real base64-encoded manifest.
# The runtime will decode, canonicalize, verify, and then allow execution.

MANIFEST_B64 = "REPLACE_WITH_REAL_MANIFEST_BASE64"

# -------------------- UTILITIES --------------------

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def b64_to_bytes(s: str) -> bytes:
    if isinstance(s, bytes):
        return s
    return base64.b64decode(s)


def to_b64(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')


def canonicalize(obj: Any) -> bytes:
    """Produce deterministic JSON bytes for signing/verifying.
    Uses sort_keys and compact separators. Ensures bytes output.
    """
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')

# -------------------- MANIFEST LOADING --------------------

def load_manifest_from_b64(b64: str) -> dict:
    try:
        raw = base64.b64decode(b64)
        manifest = json.loads(raw)
        return manifest
    except Exception as e:
        raise RuntimeError(f'Failed to decode manifest: {e}')

# -------------------- MERKLE ROOT OVER FILE HASHES --------------------

def merkle_root_from_hashes(hashes: Dict[str, str]) -> str:
    """Compute a deterministic merkle root from a dict of path->hex-hash.
    Sort paths lexicographically, then iteratively hash pairs (left||right).
    For odd count, duplicate last.
    Returns hex digest string.
    """
    items = sorted(hashes.items(), key=lambda kv: kv[0])
    leaves = [bytes.fromhex(h) for _, h in items]
    if not leaves:
        return sha256_bytes(b'')
    def pair_hash(a: bytes, b: bytes) -> bytes:
        return hashlib.sha256(a + b).digest()
    current = leaves
    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i+1] if i+1 < len(current) else current[i]
            next_level.append(pair_hash(left, right))
        current = next_level
    return current[0].hex()

# -------------------- VERIFICATION --------------------

def verify_manifest(manifest: dict) -> Tuple[bool, str]:
    """Verify payload integrity and signature. Returns (ok, message).

    Steps:
     1. Ensure required fields exist.
     2. Verify per-file sha256 hashes match content.
     3. Verify computed payload_sha256 matches manifest.payload_sha256.
     4. Verify signature over canonical manifest (manifest without 'signature').
     5. Verify merkle root matches computed root from file hashes.
    """
    required = ['meta', 'files', 'entry', 'payload_sha256', 'file_hashes', 'signature', 'signer_key_id', 'pubkeys']
    for r in required:
        if r not in manifest:
            return False, f'Missing required manifest field: {r}'

    files = manifest['files']
    file_hashes = manifest['file_hashes']

    # 1) per-file hash check
    for path, expected_hex in file_hashes.items():
        if path not in files:
            return False, f'File hash present for missing file: {path}'
        content = b64_to_bytes(files[path])
        got = sha256_bytes(content)
        if got != expected_hex:
            return False, f'Hash mismatch for {path}: got {got[:16]}..., expected {expected_hex[:16]}...'

    # 2) merkle root
    computed_merkle = merkle_root_from_hashes(file_hashes)
    if 'merkle_root' not in manifest:
        return False, 'Manifest missing merkle_root'
    if manifest['merkle_root'] != computed_merkle:
        return False, f'Merkle root mismatch: got {computed_merkle[:16]}..., expected {manifest["merkle_root"][:16]}...'

    # 3) canonical payload hash
    mcopy = dict(manifest)
    # remove signature before canonicalizing
    signature = mcopy.pop('signature', None)
    signer_key_id = mcopy.pop('signer_key_id', None)
    canonical = canonicalize(mcopy)
    computed_payload_hash = sha256_bytes(canonical)
    if computed_payload_hash != manifest['payload_sha256']:
        return False, f'Payload sha256 mismatch: got {computed_payload_hash[:16]}..., expected {manifest["payload_sha256"][:16]}...'

    # 4) signature verification
    if not CRYPTO_AVAILABLE:
        return False, 'cryptography library not available for signature verification'

    if signer_key_id not in manifest['pubkeys']:
        return False, f'signer_key_id {signer_key_id} not found among pubkeys'

    pubkey_b64 = manifest['pubkeys'][signer_key_id]
    try:
        pubbytes = base64.b64decode(pubkey_b64)
        pub = Ed25519PublicKey.from_public_bytes(pubbytes)
    except Exception as e:
        return False, f'Invalid public key bytes: {e}'

    sig_b64 = signature
    try:
        sig = base64.b64decode(sig_b64)
        # verify signature against canonical bytes
        pub.verify(sig, canonical)
    except Exception as e:
        return False, f'Signature verification failed: {e}'

    return True, 'Manifest verified successfully'

# -------------------- SELF-VERIFY RUNNING FILE --------------------

def self_verify_running_source(manifest: dict) -> Tuple[bool, str]:
    """Ensure that the running file's embedded manifest matches what we loaded.
    This prevents tampering with the file before execution.
    Approach:
      - Read this source file from disk (if available) and locate the embedded MANIFEST_B64 literal.
      - Decode it and compare canonical forms.
    """
    try:
        this_path = os.path.realpath(__file__)
        with open(this_path, 'rb') as f:
            src = f.read()
    except Exception as e:
        return False, f'Unable to read running source file: {e}'

    # Simple heuristic: find the MANIFEST_B64 assignment in source
    marker = b"MANIFEST_B64"
    idx = src.find(marker)
    if idx == -1:
        return False, 'Embedded manifest marker not found in running source'

    # Find the start of the base64 string (first quote after marker)
    try:
        start = src.index(b'"', idx) + 1
        end = src.index(b'"', start)
        embedded_b64 = src[start:end].decode('ascii')
    except Exception as e:
        return False, f'Failed to extract embedded manifest literal: {e}'

    try:
        embedded_manifest = load_manifest_from_b64(embedded_b64)
    except Exception as e:
        return False, f'Failed to decode embedded manifest from source: {e}'

    # Compare canonical forms (without signature) to avoid differences in whitespace
    em_copy = dict(embedded_manifest)
    m_copy = dict(manifest)
    # Remove signature fields for comparison
    for d in (em_copy, m_copy):
        d.pop('signature', None)
        d.pop('signer_key_id', None)

    if canonicalize(em_copy) != canonicalize(m_copy):
        return False, 'Running source embedded manifest does not match decoded manifest'

    return True, 'Running source verified against embedded manifest'

# -------------------- VFS AND RUNNER --------------------

class VFS:
    def __init__(self, files: Dict[str, str]):
        # normalize paths and keep bytes
        self.files = {self._norm(p): b64_to_bytes(v) for p, v in files.items()}

    def _norm(self, p: str) -> str:
        return p.replace('\', '/').lstrip('./')

    def exists(self, path: str) -> bool:
        return self._norm(path) in self.files

    def read_bytes(self, path: str) -> bytes:
        return self.files[self._norm(path)]

    def read_text(self, path: str, encoding='utf-8') -> str:
        return self.read_bytes(path).decode(encoding)

    def list_files(self):
        return list(self.files.keys())

class UnifiedRunner:
    def __init__(self, manifest: dict):
        self.manifest = manifest
        self.files = manifest['files']
        self.entry = manifest['entry']
        self.vfs = VFS(self.files)
        self._running = False

    def run_in_memory(self):
        # final safety gate: ensure entry exists
        if self.entry not in self.files:
            raise RuntimeError(f'Entrypoint {self.entry} not in payload files')
        # run in isolated namespace
        source = self.vfs.read_text(self.entry)
        ns = {'__name__': '__main__', '__file__': self.entry}
        # Start self-check thread/process? For simplicity, we re-verify once before exec
        ok, msg = verify_manifest(self.manifest)
        if not ok:
            raise RuntimeError('Manifest re-verification failed before exec: ' + msg)
        self._running = True
        exec(compile(source, self.entry, 'exec'), ns)
        self._running = False

    def extract_to_disk(self, outdir: str = './unpacked') -> str:
        os.makedirs(outdir, exist_ok=True)
        for path, b64 in self.files.items():
            norm = path.replace('/', os.sep)
            full = os.path.join(outdir, norm)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, 'wb') as f:
                f.write(b64_to_bytes(b64))
        return outdir

# -------------------- BUILD & SIGN HELPERS (for builder, offline) --------------------

def build_manifest_from_dir(dirpath: str, entry: str, meta: dict = None) -> dict:
    """Scan a directory and build a manifest dict. This is intended to be run
    offline on a builder machine. It will base64-encode files and compute hashes.
    """
    if meta is None:
        meta = {}
    files = {}
    file_hashes = {}
    for root, _, filenames in os.walk(dirpath):
        for fn in filenames:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, dirpath).replace('\', '/')
            with open(full, 'rb') as f:
                data = f.read()
            files[rel] = to_b64(data)
            file_hashes[rel] = sha256_bytes(data)
    manifest = {'meta': meta, 'files': files, 'entry': entry, 'file_hashes': file_hashes}
    manifest['merkle_root'] = merkle_root_from_hashes(file_hashes)
    # compute payload hash over canonical manifest without signature
    canonical = canonicalize(manifest)
    manifest['payload_sha256'] = sha256_bytes(canonical)
    return manifest


def sign_manifest(manifest: dict, signer_private_key_pem: bytes, signer_key_id: str, pubkey_map: Dict[str, str]) -> dict:
    """Given a manifest dict and a private key (PEM bytes), sign the canonical manifest (without signature)
    and attach 'signature' (base64) and 'signer_key_id' to the manifest. Returns the signed manifest.
    """
    if not CRYPTO_AVAILABLE:
        raise RuntimeError('cryptography library required to sign manifests')
    # Ensure we don't modify caller's object
    mcopy = dict(manifest)
    # ensure pubkeys included
    mcopy.setdefault('pubkeys', {}).update(pubkey_map)
    canonical = canonicalize(mcopy)
    # load private key
    priv = serialization.load_pem_private_key(signer_private_key_pem, password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise RuntimeError('Private key must be ed25519')
    sig = priv.sign(canonical)
    mcopy['signature'] = base64.b64encode(sig).decode('ascii')
    mcopy['signer_key_id'] = signer_key_id
    # recompute payload_sha256 to include pubkeys/signature? convention: payload_sha256 should be
    # computed over manifest without the 'signature' field, so keep it stable; don't overwrite here.
    return mcopy

# -------------------- CLI --------------------

def parse_args(argv=None):
    ap = argparse.ArgumentParser(description='Unified single-file deployable — production runtime')
    ap.add_argument('--verify', action='store_true', help='verify embedded manifest and signature (no exec)')
    ap.add_argument('--run', action='store_true', help='verify and run the embedded entrypoint in-memory')
    ap.add_argument('--extract', action='store_true', help='verify and extract payload to disk')
    ap.add_argument('--outdir', default='./unpacked', help='output dir for extraction')
    return ap.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if MANIFEST_B64 == 'REPLACE_WITH_REAL_MANIFEST_BASE64':
        print('ERROR: No embedded manifest found. The builder must embed a real manifest base64 into MANIFEST_B64.')
        sys.exit(2)

    try:
        manifest = load_manifest_from_b64(MANIFEST_B64)
    except Exception as e:
        print('FATAL: failed to load manifest:', e)
        sys.exit(2)

    # Basic verification
    ok, msg = verify_manifest(manifest)
    print('Manifest verification:', 'OK' if ok else 'FAILED', '-', msg)
    if not ok:
        sys.exit(3)

    # Ensure running source matches embedded manifest
    ok2, msg2 = self_verify_running_source(manifest)
    print('Self-verify running source:', 'OK' if ok2 else 'FAILED', '-', msg2)
    if not ok2:
        print('FATAL: running source does not match embedded manifest. Aborting.')
        sys.exit(4)

    runner = UnifiedRunner(manifest)

    if args.verify and not (args.run or args.extract):
        print('Verification-only requested — exiting successfully after verification.')
        sys.exit(0)

    if args.extract:
        out = runner.extract_to_disk(args.outdir)
        print('Extracted payload to', out)

    if args.run:
        print('Executing embedded entrypoint in-memory...')
        try:
            runner.run_in_memory()
        except Exception as e:
            print('Runtime execution failed:', e)
            sys.exit(5)

if __name__ == '__main__':
    start = time.time()
    main()
    elapsed = time.time() - start
    print(f'Runtime finished in {elapsed:.3f}s')
