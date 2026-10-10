# RSA-SHA256 delivery proposal

Status: platform-backend strategy approved with operational key validation;
compiler optional-dependency support implemented; RSA implementation pending.
Date: 10 October 2026.

Decision: proceed with Apple Security, Windows CNG and Linux OpenSSL EVP.
The [executed backend check](RSA-FEASIBILITY.md) found that Apple can use keys
with inconsistent redundant components. The user approved operational validation
instead of auditing every component. This finding no longer blocks that strategy.
Private imports must pass strict encoding/policy checks, backend import and an
in-process sign/verify consistency check. Windows runtime acceptance remains open.

The agreed requirements are recorded in [RSA-REQUIREMENTS.md](RSA-REQUIREMENTS.md).
This proposal resolves implementation choices and identifies the delivery dependency
before changing the public API, as requested in the platform requirements.

## Current evidence

- `crypto/doof.json` builds `doof_crypto.cpp` and copies `doof_crypto.hpp`.
  It declares no cryptographic library dependencies.
- `SecretBytes` is a native managed byte buffer. There are no RSA key handles.
- `DOOF_STDLIB_ROOT=/Users/andrew/develop/doof-stdlib doof test crypto`
  passes all 38 tests using Doof 0.3.0 on macOS.
- Compiler native manifests now support `optionalPkgConfigPackages` entries
  with `name`, `define`, package-local `.cpp` `probeSource` and optional
  `minimumVersion`. Target-toolchain compile/link probes select an explicit
  zero/one define and commit dependency flags only on success. Mandatory
  `pkgConfigPackages` retain their existing failure behavior.
- The 13 focused compiler tests cover metadata/header/API/library absence,
  version checks, failed tools, source copying, target argument planning and an
  available/unavailable/available native consumer rebuild. An installed-compiler
  libcrypto consumer on macOS built with and without metadata while preserving
  its SHA-256 output. This establishes the compiler mechanism, not Linux RSA
  runtime or cross-platform signing acceptance.
- `spec/11-modules.md` permits bounded standard-library preparation of
  already-present vendored sources. It does not acquire dependencies.
- Quark records the dependency gap, proposal review and executed Apple/EVP
  feasibility results. RSA implementation and Windows runtime evidence remain open.

The missing-dependency behavior is intentional for a mandatory dependency, not
an identified compiler defect. Making OpenSSL mandatory for all crypto imports
would violate the proposed unavailable-backend contract.

## Recommended strategy

Use Apple Security on macOS, Windows CNG on Windows, and OpenSSL EVP on Linux.
Keep hashing, randomness, encodings, HMAC and JWT implementations intact.

| Target | Signing backend | Build inputs | Runtime dependency |
| --- | --- | --- | --- |
| macOS | Apple Security `SecKey` | Security/CoreFoundation SDK frameworks | OS frameworks |
| Linux | OpenSSL EVP | libcrypto headers and pkg-config metadata | compatible libcrypto shared library |
| Windows | CNG `BCrypt` | Windows SDK, bcrypt library | OS bcrypt library |
| iOS device/simulator | unavailable initially | portable stub only | none added |
| WebAssembly | unavailable initially | portable stub only | none added |
| Other supported targets | unavailable initially | portable stub only | none added |

Apple mobile is technically a candidate for the Security backend but remains
explicitly unavailable until mobile build, validation and lifecycle tests pass.
WebAssembly has no equivalent backend in this proposal; it keeps the complete
existing crypto API and recoverable RSA capability errors.

The Linux build needs an **optional** libcrypto dependency whose detection result
selects the EVP implementation or the unavailable stub. The compiler now provides
that build contract; crypto must add its Linux entry and an OpenSSL 3 API probe.
Use `DOOF_CRYPTO_RSA_EVP` as the define and test its value with `#if`, since both
zero and one are explicitly defined. The probe must exclude LibreSSL, check the
header version and reference the required EVP signing/verification symbols.
Absence of headers/metadata must permit a stub build. After successful detection,
unrelated compiler/linker failures must remain build errors rather than silently
disabling RSA. Removing a library required by an already-linked executable is a
deployment failure; this proposal does not provide optional runtime loading.

Use an upstream-supported OpenSSL release, preferably 3.5 LTS. Allow a
distribution-maintained 3.x release only with an explicit vendor support policy.
Require the EVP validation APIs introduced in 3.0; do not silently use 1.1.1 or
LibreSSL. OpenSSL 3.x is Apache-2.0 licensed. System SDK backends add no bundled
third-party implementation. The module remains ISC licensed.

Backend references:

- [Apple key import and PKCS#1 representations](https://developer.apple.com/documentation/security/storing-keys-as-data?language=objc).
- [Windows CNG key import](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptimportkeypair).
- [OpenSSL EVP digest signing](https://docs.openssl.org/3.6/man3/EVP_DigestSignInit/).
- [OpenSSL key validation](https://docs.openssl.org/3.6/man3/EVP_PKEY_check/).
- [OpenSSL releases, licensing and support dates](https://www.openssl-library.org/source/).

### Alternative without optional pkg-config support

Bundle a pinned OpenSSL source release and statically link libcrypto on all three
desktop platforms. Ship its license and reproducible target preparation scripts
with the standard library. Use stubs on mobile, Wasm and other unsupported targets.
This avoids three backend implementations and application runtime libraries, but
adds third-party source size, OpenSSL build tooling, security-update ownership,
and changes to the compiler's curated standard-library release bundle.

Both strategies require release integration in `doof-lang`; the recommended
strategy's compiler optional dependency contract is now implemented.

## Public API and policy

Keep the proposed `RsaPrivateKey.fromPem(SecretBytes)`,
`RsaPrivateKey.signSha256Pkcs1v15(readonly byte[])`,
`RsaPublicKey.fromPem(readonly byte[])`, and
`RsaPublicKey.verifySha256Pkcs1v15(data, signature)` names and contracts.

Introduce `CryptoErrorKind` with `InvalidKey`, `UnsupportedKeyType`,
`EncryptedPrivateKey`, `KeyPolicyRejected`, `CapabilityUnavailable`, and
`BackendFailure`. A `CryptoError` contains `kind` and a sanitized, static-context
`message`; backend diagnostics must not include input contents. Unknown backend
verification errors must not be automatically converted to a mismatch.

Proposed limits: RSA modulus 2048 through 8192 bits inclusive; PEM input at most
32,768 bytes, including surrounding whitespace. Check PEM length before decoding;
inspect bounded DER to check modulus size before backend import and the signing
consistency check. Limit violations return `KeyPolicyRejected`.

Use two-prime RSA keys with an odd public exponent from 3 through `2^64 - 1`;
65537 is the normal interoperable choice. Reject multi-prime keys and exponents
outside that range as `KeyPolicyRejected`. Public modulus must be positive and
odd, and the exponent must be less than it. These are bounded representation
and policy checks, not RSA arithmetic or exhaustive public-key validation.

Strictly accept one matching supported PEM block, with surrounding ASCII
whitespace only. Reject duplicate blocks, mismatched delimiters, unexpected
headers, invalid Base64, trailing content and trailing DER. Recognize encrypted
PKCS#8 and legacy PEM encryption headers without invoking a password callback.
Reject non-RSA algorithms and restricted RSA-PSS keys as `UnsupportedKeyType`.
Malformed encodings, backend-rejected material and failed private signing
consistency checks return `InvalidKey`. Operational failures such as unavailable
randomness remain `BackendFailure`; do not relabel every backend error as bad input.

Prefer Doof for envelope checks and policy. Native code owns direct access to
secret storage, bounded DER format adaptation and platform operations. Do not
copy private PEM into strings or ordinary public byte arrays. A strict shared
DER reader may unwrap PKCS#8/SPKI for platform import but must not implement RSA
arithmetic or padding. After importing a private key, sign a fixed, public test
message with SHA-256/PKCS#1 v1.5 and verify it using the imported key's public
components through the backend. Perform this once during import, not per caller
signature. Public import uses structural/policy and backend import checks.

Do not add exhaustive component validation solely to reject material unused by
the signing backend. Such redundant components may be accepted, ignored or
normalized differently across platforms. Cross-platform parity applies to valid
supported keys and signatures, encoding/policy errors and recoverable operation
behavior, not every mathematically inconsistent input. The consistency check
does not establish primality or certify key strength.

Key handles own only backend objects and synchronization. No key-component
fields, export methods or key-material metadata enter the public API. Use native
RAII for handles and operation contexts, including failed imports. Imported keys
own their material independently of caller PEM; import never wipes caller input.

Serialize operations per key with a native mutex. This gives a clear shared-key
concurrency contract without relying on provider-specific thread safety. Use
fresh contexts per operation and retain the key throughout the call. Do not mark
methods `isolated` until the compiler concurrency contract and every backend
implementation have been verified. Caller mutation/wiping of import storage must
not race import; subsequent source wiping is safe.

Use backend signing protections, including established RSA blinding. Clear
temporary private PEM/DER/CNG blobs through non-optimizable platform or backend
wiping; document that provider internals, allocator behavior and caller copies
cannot be given an absolute erasure guarantee.

## Delivery sequence and gates

1. Backend strategy agreed: platform APIs on macOS/Windows, optional EVP on Linux;
   use operational import validation as specified above.
2. Compiler optional dependency support implemented and focused-tested.
   Bind selection to the target toolchain, check compatible headers/APIs, emit a
   backend-selection define and include resolved flags/defines in native cache
   identity. Test missing pkg-config/metadata/headers, incompatible libraries,
   cross-target metadata and available/unavailable incremental transitions.
   Add the Linux crypto manifest entry and bounded OpenSSL API probe with the
   RSA backend sources; real Linux and installed-bundle acceptance remain gates.
3. Add typed errors, opaque handles, strict import/policy validation and a stub.
   Validate native ABI lowering, serialization exclusion and resource ownership.
   Stop and report any compiler defect with a minimal reproducer to Quark.
4. Add desktop signing and verification. Hash original message bytes exactly
   once and explicitly select SHA-256 with PKCS#1 v1.5 padding. Check signature
   length before verification; malformed/nonmatching signatures return false.
5. Add independently generated disposable fixtures and public API tests.
6. Run release-bundle/offline consumer checks and the complete target matrix.
7. Document installation, runtime libraries, limits, errors, erasure and
   concurrency; provide import-once/sign/Base64/recoverable-error example.

Acceptance evidence must include:

- PKCS#1 and PKCS#8 private keys, SPKI and PKCS#1 public keys, identical
  independently generated signature bytes, and 2048/3072/4096-bit fixtures.
- Empty, UTF-8, embedded-zero and arbitrary binary messages; wrong keys,
  modified messages/signatures, truncated and oversized signatures.
- All import error categories, malformed DER, backend-rejected or operationally
  unusable keys, encrypted keys, ambiguity, key-size/PEM-size bounds, prime-count
  and exponent policy. Record acceptance of inconsistent redundant components
  without requiring identical rejection on each backend.
- Source wipe after import, repeated operations, native failure-path leak checks
  and concurrent use under sanitizers where supported.
- macOS/Linux/Windows parity against the same fixtures. macOS alone cannot
  establish cross-platform acceptance.
- An executable run with `openssl` absent from PATH. Fixture generation may
  use independent tools offline; production API/tests require no executable.
- Linux without libcrypto development metadata, stub targets and installed
  offline standard-library bundles, alongside all current crypto regressions.

## Reproduction of the build dependency gap

Using Doof 0.3.0, create a hashing-only package with:

```json
{
  "name": "rsa-dependency-repro",
  "build": { "native": { "pkgConfigPackages": ["libcrypto"] } }
}
```

Its `main.do` imports `sha256HexString` from `std/crypto` and prints the hash of
`"hello"`. With an empty pkg-config metadata directory:

```sh
PKG_CONFIG_LIBDIR=/private/tmp/doof-rsa-dependency-repro/empty-pkgconfig \
PKG_CONFIG_PATH='' DOOF_STDLIB_ROOT=/Users/andrew/develop/doof-stdlib \
doof build /private/tmp/doof-rsa-dependency-repro \
  -o /private/tmp/doof-rsa-dependency-repro/build
```

Actual: exit 1, `pkg-config could not resolve package "libcrypto"`.
Required for an optional RSA dependency: build succeeds, hashing remains usable,
and RSA import returns `CapabilityUnavailable`. This reproducer exercises a
mandatory root-package dependency; the driver uses the same aggregated native
dependency list for dependencies declared by standard-library packages.
