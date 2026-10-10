# Requirements: RSA-SHA256 signing and verification in `std/crypto`

Status: approved for implementation with operational key validation

Date: 10 October 2026

Audience: Doof standard library maintainers

## Purpose

Add in-process RSA signing and verification to `std/crypto`, so Doof applications can authenticate requests without launching an external `openssl` executable.

The initial consumer is an Oracle Cloud Infrastructure (OCI) REST client. It currently hashes request bodies with `std/crypto`, constructs the OCI signing text, and invokes `openssl dgst -sha256 -sign ... -sigopt rsa_padding_mode:pkcs1` to obtain a signature. The application then Base64-encodes the signature for the Authorization header.

This proposal adds general cryptographic capabilities. OCI request canonicalization, HTTP headers, configuration, file loading, and Base64 presentation remain application responsibilities.

## Required scope

1. Import unencrypted RSA private keys from PEM, supporting PKCS#1 (`RSA PRIVATE KEY`) and PKCS#8 (`PRIVATE KEY`).
2. Import RSA public keys from PEM, supporting SubjectPublicKeyInfo (`PUBLIC KEY`) and PKCS#1 (`RSA PUBLIC KEY`).
3. Sign arbitrary bytes using RSASSA-PKCS1-v1_5 with SHA-256.
4. Verify signatures using the same scheme.
5. Provide reusable, opaque native key handles with automatic resource cleanup.
6. Return recoverable failures through `Result`; invalid external input must not panic or terminate the process.
7. Perform all operations in process, without shell commands, helper executables, or temporary files.

The algorithm name must identify both SHA-256 and PKCS#1 v1.5 padding. RSA-PSS is a different scheme and must not be substituted or selected implicitly.

## Proposed public API

The following is an API sketch; exact names may be adapted to standard-library conventions while preserving these contracts.

```doof
export class RsaPrivateKey {
    static fromPem(pem: SecretBytes): Result<RsaPrivateKey, CryptoError>
    signSha256Pkcs1v15(data: readonly byte[]): Result<readonly byte[], CryptoError>
}

export class RsaPublicKey {
    static fromPem(pem: readonly byte[]): Result<RsaPublicKey, CryptoError>
    verifySha256Pkcs1v15(
        data: readonly byte[], signature: readonly byte[]
    ): Result<bool, CryptoError>
}
```

- Signing accepts the original message bytes and hashes them internally exactly once. It must not expect a precomputed digest.
- Signing returns raw signature bytes. Existing encoding functions handle Base64 or hex.
- Verification returns `Success(true)` for a valid signature and `Success(false)` for a nonmatching or malformed signature, including an incorrect signature length. Backend or operational failures return `Failure`.
- Empty messages and arbitrary binary data are supported. There is no implicit text encoding, normalization, or newline conversion.
- Key import checks the encoding, RSA key type, security policy and suitability for the requested operation. Import rejects malformed, truncated, unsupported or ambiguous encodings rather than silently choosing a key. Private-key import performs an in-process sign/verify consistency check through the backend before returning a handle.
- Import accepts surrounding whitespace but requires exactly one supported PEM key block; additional key blocks or non-whitespace trailing content are rejected.
- Imported keys remain usable after the caller wipes the input `SecretBytes`. The importer does not consume or wipe the caller's input implicitly; callers retain responsibility for wiping it.
- Repeated operations reuse the imported key. There must be no PEM parsing per signature.
- Key handles must not expose private components or support accidental serialization, logging, or string conversion that reveals key material.
- The team must document concurrency semantics. Calls sharing a key must either be safe or serialized internally; there must be no native data races. Mark operations `isolated` only if the implementation satisfies that contract.

## Errors and key policy

Use a structured `CryptoError` or an equivalent typed error contract. Callers must be able to distinguish:

- Invalid key format, backend-rejected material or a failed private-key consistency check.
- Unsupported key type or algorithm.
- Encrypted private key unsupported.
- Key rejected by the security policy.
- Capability unavailable on the target.
- Backend operation failure.

Error messages must be useful without including PEM contents, private components, message contents, or signatures. An encrypted-key import must fail promptly without prompting for a password or attempting interactive input.

Support at least 2048-, 3072-, and 4096-bit RSA keys. Reject keys below 2048 bits for this initial API. Define and document an upper bound for key sizes and PEM input length to limit resource consumption; exceeding a limit returns a recoverable error. Reject structurally invalid encodings and apply backend import checks appropriate to the supported key format.

Applications are expected to supply valid keys generated by established tooling.
Import establishes an operational key, not an exhaustive mathematical audit of
every supplied RSA component. Redundant components that a backend does not use
may be ignored or normalized; their inconsistency alone need not cause rejection.
Backend behavior for such components may differ by platform. The private-key
sign/verify check demonstrates the imported signing path and matching public key;
it does not prove primality, validate every component or certify key strength.
No bespoke RSA arithmetic or additional validation library is required to enforce
those stronger properties. Bounded parsing, recoverable errors, resource cleanup
and the prohibition on input-induced panics remain requirements.

## Implementation and dependency requirements

Use a maintained cryptographic backend or platform API. Do not implement RSA arithmetic, padding, or private-key operations from scratch in Doof or bespoke C++.

The backend strategy is a team decision. Platform APIs on Apple and Windows and OpenSSL's EVP APIs on Linux are acceptable candidates, subject to equivalent behavior across platforms. A bundled maintained library is also acceptable.

Required properties:

- Protect private-key operations against timing attacks through the backend's established protections, including blinding where applicable.
- Release native key objects and per-operation resources automatically, including on failures.
- Minimize private-key copies; clear temporary private-key buffers with a mechanism that cannot be optimized away. Document backend limits on erasure guarantees.
- Keep backend types out of the public Doof API.
- Package native sources and build metadata with the standard library. Applications must not supply their own C++ bridge or discover an executable at runtime.
- Document library dependencies, supported versions, licensing, and release/build integration. If a shared library is required at runtime, state that explicitly.
- Preserve existing hashing, HMAC, encoding, randomness, and JWT behavior.

Removing the `openssl` executable dependency does not require eliminating every native library dependency. The deliverable must clearly distinguish build-time dependencies, runtime libraries, and bundled components.

## Platform requirements

The initial release must support macOS, Linux, and Windows native targets. Apple mobile and WebAssembly support must be explicitly assessed and documented.

On any supported Doof target lacking a signing backend, the API must remain importable and return a clear capability-unavailable failure. Importing `std/crypto` for existing functionality must not become a build or link failure because RSA is unavailable. Do not silently fall back to a subprocess.

If this contract requires compiler or build-system support, identify that dependency before implementation and agree a delivery plan.

## Acceptance tests

Tests must use public, disposable test keys and independently generated fixtures. No OCI credentials or network access are required.

1. **Independent interoperability:** a known message and key produce the exact independently generated PKCS#1 v1.5/SHA-256 signature; verification accepts that signature. PKCS#1 v1.5 signing is deterministic.
2. **Formats:** both supported private-key formats produce the same signature for the same key and message; both public-key formats verify it.
3. **Key sizes:** signing and verification work with 2048-, 3072-, and 4096-bit fixtures.
4. **Bytes:** empty messages, UTF-8 bytes, embedded zero bytes, and binary inputs sign and verify correctly.
5. **Mismatch handling:** modified messages, modified signatures, signatures of incorrect length, and the wrong public key return `Success(false)`.
6. **Import failures:** malformed/truncated PEM, invalid DER, non-RSA keys, encrypted private keys, multiple blocks, unexpected trailing content, undersized keys, and inputs exceeding documented limits return the expected error categories. Private keys whose backend import or sign/verify consistency check fails are rejected recoverably. Acceptance of inconsistent redundant components is permitted and documented; rejection parity for those components is not required.
7. **Lifecycle:** one imported key signs multiple messages; wiping the source `SecretBytes` does not invalidate the key; import and operation failures do not leak native resources. Validate the documented concurrency behavior.
8. **Cross-platform parity:** the same key and message produce identical signature bytes on each required native target, and signatures verify across those targets.
9. **No executable dependency:** signing and verification work in an environment with no `openssl` executable available.
10. **Regression:** existing `std/crypto` tests pass. Targets without RSA support retain existing crypto functionality and exhibit the documented unavailable-capability behavior.

The OCI client already has an independent RSA-SHA256 fixture for the message `Doof OCI signing fixture`. It can be supplied as an additional interoperability check, but this standard-library change must have its own self-contained fixtures and tests.

## Consumer migration and completion criteria

The release must include API documentation and an example showing private-key import, signing raw bytes, Base64 encoding, and recoverable error handling.

The OCI client should be able to read its configured PEM file into secret storage, import the key once, and replace its subprocess signer with this API while preserving its signature output. The client must continue to own signing-text construction and HTTP behavior.

The work is complete when the required native platforms pass the acceptance tests, dependencies and unavailable-target behavior are documented, and a consumer can sign an OCI-compatible request without an external executable or application-owned native code.

## Out of scope for this change

- Key generation, export, rotation, certificate parsing, or certificate validation.
- Password-protected PEM support.
- RSA encryption/decryption, RSA-PSS, ECDSA, or Ed25519.
- JWT RS256 convenience functions, cloud-specific signers, or HTTP signature frameworks.
- Hardware-backed keys, keychain integration, HSMs, or remote signing services.
- A claim of FIPS certification or compliance.

These may be added later through separate requirements. The initial API should permit extension without changing the meaning of its existing algorithm-specific methods.

## References

- [OCI request signatures](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm): the motivating protocol and signing-string requirements.
- [OCI API signing keys](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm): RSA PEM key requirements.
- [OpenSSL EVP digest signing](https://docs.openssl.org/3.6/man3/EVP_DigestSignInit/): a candidate maintained backend API.

The API, security policy, and acceptance criteria above are proposed Doof requirements, rather than claims that these sources prescribe a particular Doof implementation.
