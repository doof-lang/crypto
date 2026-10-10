# RSA backend validation feasibility

Date: 10 October 2026.
Verdict under the original contract: **Apple Security import alone does not
validate every supplied private component.**

Decision after review: the user approved operational validation and proceeding
with platform backends. This removes the exhaustive component-validation gate.
Strict encoding/policy checks and a backend sign/verify check on private import
remain required. The measurements below are unchanged; they explain the accepted
limits rather than block the revised strategy.

## Executed experiment

Host: macOS 27.0.1 (26A434), arm64. Oracle: Homebrew OpenSSL 3.6.4.
The standalone [native probe](../tests/native/rsa-feasibility.cpp) generates
disposable two-prime RSA keys in process; it writes no key files and uses no
credentials. This is a feasibility experiment, not production cryptographic code
or a public Doof API test.

For each of 2048, 3072, 4096 and 8192 bits, the probe:

- Encodes PKCS#1 private/public DER through OpenSSL.
- Independently flips bit 1 of the last byte of each private INTEGER component:
  `n`, `e`, `d`, `p`, `q`, `dP`, `dQ`, `qInv`. Lengths, DER signs and parity
  are preserved, while the mathematical consistency is broken.
- Compares `EVP_PKEY_check` with `SecKeyCreateWithData` private import and
  SHA-256/PKCS#1 v1.5 message signing against the original-key signature.
- Tests public import with an even modulus and even exponents 65536 and 65538,
  comparing with `EVP_PKEY_public_check`.
- Tests truncation and an appended DER zero byte.
- Confirms original-key signature parity for empty, ASCII and binary messages.

The 60-row [result matrix](../tests/native/rsa-feasibility-macos.csv) records
the complete four-size run. Private signature result: `1` = identical to the
original-key oracle, `0` = different, `-1` = signing failed, `-2` = no imported
key. Public rows record verification of the original signature instead.

| Case, at all four sizes | EVP check | Apple import | Apple operation |
| --- | --- | --- | --- |
| Valid private key | accepts | accepts | identical signature |
| Mutated private `d` | rejects | accepts | **identical signature** |
| Other seven private component mutations | rejects | accepts | signing fails |
| Valid public key | accepts | accepts | verifies |
| Even public modulus | rejects | rejects | unavailable |
| Even public exponent | rejects | accepts | verification fails |
| Truncated private DER | decode fails | rejects | unavailable |
| Private DER with trailing zero | accepts parsed prefix | accepts | identical signature |

An additional 2048-bit run exported imported Apple keys using
`SecKeyCopyExternalRepresentation`. Every component-mutated key exported
byte-identical DER, including the invalid `d`. Thus neither sign/verify self-tests
nor import/export equality detects that corrupted exponent in this experiment.
Trailing-zero input exported without the extra byte.

The full matrix and supplemental roundtrip run completed with AddressSanitizer
and UndefinedBehaviorSanitizer enabled for the probe, with no reported findings.
System Security and the installed OpenSSL library were not rebuilt with those
sanitizers; this is not comprehensive provider memory/lifecycle validation.

## Consequences

The original contract required inconsistent supplied private components to cause
a recoverable import failure. Actual: Apple accepted all eight mutations, and invalid `d` remained
usable. Delaying rejection until a signing self-test is insufficient. Structural
DER parsing and common key policy cannot establish the missing mathematical
relationships without a cryptographic validation backend.

OpenSSL's explicit pairwise/public validation rejected every mathematical
mutation tested. Its DER decoder accepted a valid prefix with trailing content,
so strict envelope/DER consumption remains necessary even with EVP. Check
bounded key sizes before expensive validation, and handle unsupported validation
operations as failures rather than success.

The revised requirements accept an operational key instead of auditing every
supplied component. Use bounded structural/policy checks, backend import, and a
private sign/verify consistency check. Acceptance of the corrupted redundant
`d` is permitted. No extra validation library or bespoke RSA arithmetic is
required solely to reject it. This experiment compares signatures against the
original valid-key oracle; implementation must additionally exercise the actual
import-time self-test using the imported key's public components.

Bundled EVP remains an alternative if future requirements demand exhaustive
component-validation parity, but the current findings do not justify selecting
it solely for that purpose.

## Windows and remaining gates

The [CNG probe adapter](../tests/native/rsa-feasibility-cng.hpp) maps every
supplied private component into `BCRYPT_RSAFULLPRIVATE_BLOB`, uses the Microsoft
Primitive Provider with import flags zero, and selects SHA-256/PKCS#1 padding.
It deliberately avoids the smaller private blob, which omits `d` and CRT fields.
The full probe passed MinGW Windows cross-compilation syntax checks with warnings
as errors. **It has not been linked or executed on Windows.** Documentation of
`BCRYPT_NO_KEY_VALIDATION` as opting out of applicable FIPS self-tests does not
establish complete supplied-component validation with flags zero.

No Linux runtime, multi-prime/exponent-boundary, PKCS#8/SPKI wrapper, secret
erasure, concurrent-use, native ABI, or installed-bundle acceptance is claimed.
EVP was exercised on macOS, not Linux. The measurements fail the original
exhaustive Apple validation gate. That gate has now been removed; the remaining
platform and operational acceptance tests still apply.

## Reproduction

From the crypto package, using OpenSSL 3 development metadata:

```sh
clang++ -std=c++17 -Wall -Wextra -Werror \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  tests/native/rsa-feasibility.cpp $(pkg-config --cflags --libs libcrypto) \
  -framework Security -framework CoreFoundation \
  -o /private/tmp/doof-rsa-feasibility
/private/tmp/doof-rsa-feasibility
/private/tmp/doof-rsa-feasibility 2048
```

The default run covers all four sizes; the argument selects one size. Every run
generates fresh disposable keys. The oracle is an in-process library, not an
`openssl` executable. On Windows, build the same source with a Windows OpenSSL 3
development installation and `bcrypt.lib` (or MinGW `-lbcrypt`), omitting Apple
frameworks. Windows compilation/runtime setup remains a target-host task.

References: [Apple key representations](https://developer.apple.com/documentation/security/storing-keys-as-data?language=objc),
[Apple published RSA import source](https://github.com/apple-oss-distributions/Security/blob/main/OSX/sec/Security/SecRSAKey.c),
[EVP validation contracts](https://docs.openssl.org/3.6/man3/EVP_PKEY_check/),
[CNG key import](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptimportkeypair),
[CNG full private blob layout](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob).
Published Apple source is contextual evidence; this report's import behavior was
measured on the host above and is not a claim about every macOS version.
