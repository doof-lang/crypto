# std/crypto Guide

`std/crypto` provides small cryptographic building blocks for Doof programs:
SHA digests, HMAC-SHA-256, secret byte storage, random bytes, UUID v4
generation, hex/base64 encodings, and HS256 JWT parsing and verification.

The package is intentionally focused. It does not provide public-key
cryptography, password hashing, encryption modes, or a full JWT validation
framework.

## Quick Start

```doof
import { SecretBytes, hmacSha256Base64Url, sha256HexString, uuidV4 } from "std/crypto"

digest := sha256HexString("hello")
key := SecretBytes.random(32)
mac := hmacSha256Base64Url(key, [104, 101, 108, 108, 111])
requestId := uuidV4()

println(digest)
println(mac)
println(requestId)
```

Use `Result` handling for decoders and token verification because their inputs
usually come from outside the program:

```doof
import { SecretBytes, decodeBase64Url, verifyJwtHs256 } from "std/crypto"

payload := decodeBase64Url(encoded) else {
    println("invalid base64url: ${payload.error}")
    return
}

key := SecretBytes.steal([115, 101, 99, 114, 101, 116])
jwt := verifyJwtHs256(token, key) else {
    println("invalid token")
    return
}
```

## Choosing Primitives

Use SHA-256 for new digest use cases. SHA-1 is available for legacy protocols,
wire formats, and fixtures such as WebSocket accept keys, but should not be used
for new security designs.

Use HMAC-SHA-256 to authenticate bytes with a shared secret. HMAC is the right
primitive for "the holder of this secret created this value" checks. Store HMAC
keys in `SecretBytes` so the owned native buffer can be wiped.

Use `timingSafeEqual` when comparing MACs, signatures, or secret-derived byte
arrays. It compares the full input length instead of returning on the first
difference. It still returns `false` when lengths differ.

Use `uuidV4` for random identifiers, correlation IDs, and object IDs where
uniqueness is enough. A UUID is not an authentication secret; use
`SecretBytes.random` for secrets, nonces, session tokens, and HMAC keys.

## Hashing

Hash byte arrays when the payload is already binary:

```doof
import { encodeHex, sha256 } from "std/crypto"

payload: readonly byte[] := [0, 1, 2, 3]
digest := sha256(payload)
println(encodeHex(digest))
```

Hash strings with the `String` helpers. They hash the UTF-8 bytes of the string:

```doof
import { sha1HexString, sha256HexString } from "std/crypto"

legacy := sha1HexString("abc")
digest := sha256HexString("abc")
```

Use `blobStreamToSha256` when data is already available as a
`Stream<readonly byte[]>`. It hashes the concatenation of every chunk emitted by
the stream, including empty chunks:

```doof
import { blobStreamToSha256, encodeHex } from "std/crypto"

digest := blobStreamToSha256(chunks)
println(encodeHex(digest))
```

## Secret Bytes And Random Data

`SecretBytes` owns a native byte buffer. The buffer is wiped when `wipe()` is
called and again when the last reference is destroyed.

```doof
import { SecretBytes, encodeHex } from "std/crypto"

key := SecretBytes.random(32)
println(key.length())

copy := key.bytes()
println(encodeHex(copy))

key.wipe()
```

`SecretBytes.random(length)` and `randomBytes(length)` use the platform's
cryptographically secure random source. Passing a negative length is a
programmer error and panics.

`SecretBytes.steal(data)` copies bytes into secret storage and clears the
transferred native buffer. Treat the original value as consumed after calling
`steal`.

`bytes()` returns an ordinary copied `readonly byte[]`. Use it only when another
API requires raw bytes; the returned copy is not automatically wiped.

## HMAC-SHA-256

HMAC helpers accept a `SecretBytes` key and a byte array payload:

```doof
import { SecretBytes, hmacSha256, hmacSha256Base64Url, hmacSha256Hex } from "std/crypto"

key := SecretBytes.steal([115, 101, 99, 114, 101, 116])
payload: readonly byte[] := [109, 101, 115, 115, 97, 103, 101]

raw := hmacSha256(key, payload)
hex := hmacSha256Hex(key, payload)
url := hmacSha256Base64Url(key, payload)
```

`hmacSha256` returns the raw 32-byte digest. Use the `Hex` or `Base64Url`
helpers when an external protocol expects text.

## Encodings

Encoding helpers convert binary values to and from text. They do not encrypt,
authenticate, or hide data.

```doof
import { decodeHex, encodeBase64, encodeBase64Url, encodeHex } from "std/crypto"

bytes: readonly byte[] := [0, 1, 15, 16, 171, 255]

hex := encodeHex(bytes)                  // "00010f10abff"
roundTrip := try! decodeHex(hex)

b64 := encodeBase64(bytes)               // padded standard base64
b64url := encodeBase64Url(bytes)         // unpadded URL-safe base64
```

`encodeHex` always emits lowercase hex. `decodeHex` accepts uppercase and
lowercase input and returns `Failure<string>` for odd-length input or non-hex
characters.

`encodeBase64` emits standard base64 with `=` padding. `decodeBase64` accepts
padded input and unpadded input when the length can be recovered.

`encodeBase64Url` emits URL-safe base64 without `=` padding. `decodeBase64Url`
accepts padded or unpadded URL-safe input.

Base64 decoders return `Result<readonly byte[], string>` and fail when input has
invalid characters, invalid padding, or an impossible length.

## JWTs

`parseJwt(token)` decodes the three JWT segments into a `Jwt` value. It validates
the token shape, JSON header and payload, base64url encoding, and object shape,
but it does not verify the signature.

```doof
import { parseJwt } from "std/crypto"

jwt := parseJwt(token) else {
    println("malformed JWT")
    return
}

alg := jwt.header.get("alg") as string else {
    println("missing alg")
    return
}
```

`verifyJwtHs256(token, key)` parses the token, requires `alg == "HS256"`,
computes HMAC-SHA-256 over `header.payload`, and compares the raw signature with
`timingSafeEqual`.

```doof
import { SecretBytes, verifyJwtHs256 } from "std/crypto"

key := SecretBytes.steal([115, 101, 99, 114, 101, 116])
jwt := verifyJwtHs256(token, key) else {
    println("invalid token")
    return
}

sub := jwt.claims.get("sub") as string else {
    println("missing subject")
    return
}
```

JWT verification only checks the HS256 signature and algorithm. Callers are
responsible for application-level claims such as `iss`, `aud`, `exp`, `nbf`,
`iat`, and `sub`.

## Error Handling

The crypto APIs use `Result` for invalid external data:

- `decodeHex(text): Result<readonly byte[], string>`
- `decodeBase64(text): Result<readonly byte[], string>`
- `decodeBase64Url(text): Result<readonly byte[], string>`
- `decodeBase64UrlToString(text): Result<string, string>`
- `parseJwt(token): Result<Jwt, JwtError>`
- `verifyJwtHs256(token, key): Result<Jwt, JwtError>`

APIs panic for programmer errors such as negative random byte lengths.

## API

Declarations are defined in [index.do](../index.do).

### Hashes

```doof
export function sha1(data: readonly byte[]): readonly byte[]
export function sha1String(text: string): readonly byte[]
export function sha1Hex(data: readonly byte[]): string
export function sha1HexString(text: string): string

export function sha256(data: readonly byte[]): readonly byte[]
export function sha256String(text: string): readonly byte[]
export function sha256Hex(data: readonly byte[]): string
export function sha256HexString(text: string): string
export function blobStreamToSha256(source: Stream<readonly byte[]>): readonly byte[]
```

SHA-1 returns 20 bytes. SHA-256 returns 32 bytes. Hex helpers return lowercase
text.

### `SecretBytes`

```doof
export class SecretBytes
```

Methods:

- `static random(length: int): SecretBytes` creates secret random bytes.
- `static steal(data: readonly byte[]): SecretBytes` moves bytes into secret storage.
- `wipe(): void` zeroes the owned native buffer immediately.
- `bytes(): readonly byte[]` returns a copy of the owned bytes.
- `length(): int` returns the current byte length.

### HMAC And Comparison

```doof
export function hmacSha256(key: SecretBytes, data: readonly byte[]): readonly byte[]
export function hmacSha256Hex(key: SecretBytes, data: readonly byte[]): string
export function hmacSha256Base64Url(key: SecretBytes, data: readonly byte[]): string
export function timingSafeEqual(a: readonly byte[], b: readonly byte[]): bool
```

### Random Identifiers

```doof
export function randomBytes(length: int): SecretBytes
export function uuidV4(): string
```

`randomBytes` is an alias for `SecretBytes.random`. `uuidV4` returns a lowercase
RFC 4122 version 4 UUID string.

### Encodings

```doof
export function encodeHex(data: readonly byte[]): string
export function decodeHex(text: string): Result<readonly byte[], string>

export function encodeBase64(data: readonly byte[]): string
export function decodeBase64(text: string): Result<readonly byte[], string>

export function encodeBase64Url(data: readonly byte[]): string
export function decodeBase64Url(text: string): Result<readonly byte[], string>
export function decodeBase64UrlToString(text: string): Result<string, string>
```

### JWT

```doof
export class Jwt
export enum JwtError

export function parseJwt(token: string): Result<Jwt, JwtError>
export function verifyJwtHs256(token: string, key: SecretBytes): Result<Jwt, JwtError>
```

`Jwt` fields:

- `header: readonly Map<string, JsonValue>`
- `claims: readonly Map<string, JsonValue>`
- `signedContent: string`
- `signature: byte[]`

`JwtError` values:

- `MalformedToken`
- `InvalidHeader`
- `InvalidPayload`
- `AlgorithmMismatch`
- `SignatureInvalid`
