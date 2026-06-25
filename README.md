# std/crypto

Small cryptographic primitives for Doof.

This package provides SHA-1 and SHA-256 digests, HMAC-SHA-256, JWT HS256 verification, secret byte storage, random byte generation, UUID v4 generation, and text encoding utilities so packages can hash payloads, verify fixtures, generate identifiers, and move binary values through text-based interfaces.

## Documentation

- [Guide and API reference](docs/API.md) explains hashing, HMAC, secret bytes, encodings, JWT handling, random IDs, and comparison safety.
- Tests can be run with `doof test crypto`.

## Examples

### Hash UTF-8 text

```doof
import { sha1HexString, sha256HexString } from "std/crypto"

legacyDigest := sha1HexString("hello world")
strongDigest := sha256HexString("hello world")
println(strongDigest) // lowercase 64-char hex
```

### Hash raw bytes and render the digest

```doof
import { encodeHex, sha256 } from "std/crypto"

payload: readonly byte[] := [0, 1, 2, 3]
digest := sha256(payload) // 32-byte digest
println(encodeHex(digest))
```

### Hash a byte stream incrementally

```doof
import { blobStreamToSha256, encodeHex } from "std/crypto"

// `chunks` is a Stream<readonly byte[]>
digest := blobStreamToSha256(chunks)
println(encodeHex(digest))
```

`blobStreamToSha256(source)` accepts `Stream<readonly byte[]>` and hashes the concatenation of all bytes produced by the stream.

### Generate secret random bytes and a UUID

```doof
import { SecretBytes, uuidV4, encodeHex } from "std/crypto"

nonce := SecretBytes.random(16)
requestId := uuidV4()

println(encodeHex(nonce.bytes()))
println(requestId) // RFC 4122 v4, lowercase
```

`SecretBytes` owns sensitive bytes and zeroes its native buffer when `wipe()` is called or when the last reference is destroyed. `bytes()` returns a copy for APIs that need ordinary `readonly byte[]` values.

### HMAC (SHA-256)

```doof
import { SecretBytes, hmacSha256, encodeHex } from "std/crypto"

key := SecretBytes.steal([115, 101, 99, 114, 101, 116])
payload: readonly byte[] := [109, 101, 115, 115, 97, 103, 101]
mac := hmacSha256(key, payload) // raw bytes
println(encodeHex(mac))
```

Use `SecretBytes.steal(...)` or `SecretBytes.random(...)` to create keys. `hmacSha256Hex` and `hmacSha256Base64Url` return common text encodings directly.

### Verify a JWT signed with HS256

```doof
import { SecretBytes, verifyJwtHs256 } from "std/crypto"

key := SecretBytes.steal([115, 101, 99, 114, 101, 116])
jwt := verifyJwtHs256(token, key) else {
	println("invalid token")
	return
}

println(jwt.signedContent)
```

`verifyJwtHs256` always takes a `SecretBytes` key.

### Base64 and Base64Url

```doof
import { SecretBytes, encodeBase64, decodeBase64, encodeBase64Url, decodeBase64Url } from "std/crypto"

blob := SecretBytes.random(8).bytes()
b64 := encodeBase64(blob)
decoded := try! decodeBase64(b64)
println(decoded.length)

url := encodeBase64Url(blob)
decodedUrl := try! decodeBase64Url(url)
println(decodedUrl.length)
```

`decodeBase64` / `decodeBase64Url` return `Result<readonly byte[], string>` and will `Err` on invalid input.

### JWT parsing

```doof
import { parseJwt, encodeHex } from "std/crypto"

result := parseJwt(token) else {
	println("invalid token")
	return
}

jwt := result.value
println(jwt.signedContent)
println(encodeHex(jwt.signature))
```

`parseJwt` parses the three JWT parts, base64url-decodes header and payload, and returns a `Jwt` with `header`, `claims`, `signedContent` and the raw `signature` bytes.

### Decode hex back into bytes

```doof
import { decodeHex } from "std/crypto"

decoded := try! decodeHex("deadbeef")
println(decoded.length)
```

`decodeHex` accepts uppercase or lowercase hexadecimal and returns `Result<readonly byte[], string>`; it returns `Err` for invalid input (non-hex characters or odd length).

## API

- `sha1(data: readonly byte[]) -> readonly byte[]`
	- Returns the 20-byte SHA-1 digest of `data`.
- `sha1String(text: string) -> readonly byte[]`
	- Hashes the UTF-8 bytes of `text` and returns the 20-byte digest.
- `sha1Hex(data: readonly byte[]) -> string`
	- Returns the lowercase hexadecimal representation of the SHA-1 digest for `data`.
- `sha1HexString(text: string) -> string`
	- Convenience: SHA-1 of `text` (UTF-8) as lowercase hex.
- `sha256(data: readonly byte[]) -> readonly byte[]`
	- Returns the 32-byte SHA-256 digest of `data`.
- `sha256String(text: string) -> readonly byte[]`
	- Hashes the UTF-8 bytes of `text` and returns the 32-byte digest.
- `sha256Hex(data: readonly byte[]) -> string`
	- Returns the lowercase hexadecimal representation of the SHA-256 digest for `data`.
- `sha256HexString(text: string) -> string`
	- Convenience: SHA-256 of `text` (UTF-8) as lowercase hex.
- `blobStreamToSha256(source: Stream<readonly byte[]>) -> readonly byte[]`
	- Incrementally hashes the concatenated bytes from `source` and returns the 32-byte digest.
- `SecretBytes.random(length: int) -> SecretBytes`
	- Returns cryptographically-strong random bytes owned by a `SecretBytes` value.
- `SecretBytes.steal(data: readonly byte[]) -> SecretBytes`
	- Copies `data` into secret storage and zeroes the source buffer passed to the native bridge.
- `SecretBytes#wipe() -> void`
	- Zeroes the owned native buffer immediately.
- `SecretBytes#bytes() -> readonly byte[]`
	- Returns a copy of the owned bytes.
- `hmacSha256(key: SecretBytes, data: readonly byte[]) -> readonly byte[]`
	- Computes HMAC-SHA-256 over `data` using secret binary `key`.
- `hmacSha256Hex(key: SecretBytes, data: readonly byte[]) -> string`
	- Computes HMAC-SHA-256 and returns lowercase hex.
- `hmacSha256Base64Url(key: SecretBytes, data: readonly byte[]) -> string`
	- Computes HMAC-SHA-256 and returns unpadded base64url.
- `timingSafeEqual(a: readonly byte[], b: readonly byte[]) -> bool`
	- Compares byte arrays without data-dependent early exit.
- `randomBytes(length: int) -> SecretBytes`
	- Alias for `SecretBytes.random(length)`.
- `uuidV4() -> string`
	- Returns a lowercase RFC 4122 version 4 UUID string.
- `encodeHex(data: readonly byte[]) -> string`
	- Converts `data` to lowercase hexadecimal.
- `decodeHex(text: string) -> Result<readonly byte[], string>`
	- Parses hexadecimal (upper- or lower-case) into bytes; returns `Err` with an error message on invalid input.
- `verifyJwtHs256(token: string, key: SecretBytes) -> Result<Jwt, JwtError>`
	- Parses and verifies an HS256 JWT using a secret binary key.

## Notes

- `encodeHex` always emits lowercase hex.
- `decodeHex` accepts either case but will fail on non-hex characters or odd-length input.
- The random bytes generator uses the platform's cryptographically secure source.
- The UUID generator produces RFC 4122 version 4 UUIDs, which are random except for fixed version and variant bits.
