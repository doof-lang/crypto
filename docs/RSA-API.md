# RSA SHA-256 signing

`RsaPrivateKey` and `RsaPublicKey` sign and verify original message bytes with
RSASSA-PKCS1-v1_5 and SHA-256. Hashing happens exactly once internally. Signatures
are raw bytes; use `encodeBase64` for a protocol that requires text. No executable,
network access, or temporary files are used by these operations.

```doof
import { RsaPrivateKey, SecretBytes, encodeBase64 } from "std/crypto"

function sign(pem: SecretBytes, message: readonly byte[]): Result<string, string> {
    key := RsaPrivateKey.fromPem(pem) else error {
        return { error: error.message }
    }
    pem.wipe()
    signature := key.signSha256Pkcs1v15(message) else error {
        return { error: error.message }
    }
    return { value: encodeBase64(signature) }
}
```

Import once and reuse the key for multiple messages. Import does not wipe the
caller input; subsequent wiping is safe. Do not modify or wipe source storage
concurrently with import. Operations sharing one key are serialized by a native
mutex. Methods are not declared `isolated` in this first release. Keys have private
native handles and dedicated constructors, excluding automatic serialization;
there are no export or private-component access methods.

## Import and errors

Private import accepts unencrypted PKCS#1 (`RSA PRIVATE KEY`) and PKCS#8
(`PRIVATE KEY`) from `SecretBytes`. Public import accepts PKCS#1
(`RSA PUBLIC KEY`) and SubjectPublicKeyInfo (`PUBLIC KEY`) byte arrays. Exactly
one block is required, with optional surrounding ASCII whitespace. Base64 and
DER must be canonical and complete; headers, additional blocks, and trailing DER
or text are rejected. PKCS#8 attributes and optional fields are not accepted.

PEM input is limited to 32,768 bytes. Moduli must be positive, odd, and 2048–8192
bits; keys must be two-prime RSA with an odd exponent from 3 through `2^64 - 1`.
RSA-PSS, non-RSA algorithms, and encrypted private keys are unsupported. Private
import performs one backend sign/verify consistency check. This is operational
validation, not an exhaustive mathematical audit of redundant components.
Platform rejection behavior for inconsistent components can differ.

`CryptoError` contains `kind: CryptoErrorKind` and a sanitized `message`:

| Kind | Meaning |
| --- | --- |
| `InvalidKey` | Invalid encoding, backend-rejected material, or failed consistency check |
| `UnsupportedKeyType` | Unsupported PEM key type or algorithm |
| `EncryptedPrivateKey` | Password-protected input |
| `KeyPolicyRejected` | Size, exponent, or two-prime policy violation |
| `CapabilityUnavailable` | No RSA backend selected for this target |
| `BackendFailure` | An operation could not complete |

Verification returns `Success(false)` for wrong messages, wrong keys, malformed
signatures, and wrong signature lengths. Operational failures return `Failure`.
The parser still checks input on targets without a backend; valid supported keys
then return `CapabilityUnavailable`.

## Platforms and dependencies

| Target | Backend | Dependencies |
| --- | --- | --- |
| macOS | Apple Security | OS Security and CoreFoundation frameworks |
| Windows | CNG | Windows SDK at build time; OS bcrypt library at runtime |
| Linux | OpenSSL 3 EVP, when available | libcrypto development headers and pkg-config at build time; compatible libcrypto at runtime |
| iOS, Wasm, other targets | Unavailable stub | No RSA library dependency |

Linux detection requires OpenSSL 3.x, excludes LibreSSL, and compiles/links the
required API probe with the target toolchain. Use an upstream-supported release
(preferably 3.5 LTS), or a distribution-maintained version with vendor support.
Missing metadata, headers, or compatible libraries selects the stub and preserves
hashing/HMAC/encoding. Later application compile/link failures remain fatal. Once
linked, removing libcrypto is a deployment failure; there is no optional runtime
loading. Cross-builds must configure target pkg-config metadata and sysroots.

OpenSSL 3 is Apache-2.0 licensed; no OpenSSL implementation is bundled here. The
package remains ISC licensed. This package requires a compiler supporting native
`optionalPkgConfigPackages` (introduced by compiler commit `f3a9929`).

Decoded private DER and CNG import blobs are cleared with non-elidable writes,
and native handles and operation contexts use RAII. Erasure of provider internals,
allocator copies, and caller-owned buffers cannot be guaranteed. Backend private
operations provide the platform's established signing protections. This API makes
no FIPS certification claim.

See [implementation validation](RSA-VALIDATION.md) for executed checks and the
remaining platform acceptance gates.
