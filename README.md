# std/crypto

Small cryptographic primitives for Doof.

This package provides SHA-256 digests, random byte generation, UUID v4 generation, and hexadecimal encoding utilities so packages can hash payloads, verify fixtures, generate identifiers, and move binary values through text-based interfaces.

## Examples

### Hash UTF-8 text

```doof
import { sha256HexString } from "std/crypto"

digest := sha256HexString("hello world")
println(digest) // lowercase 64-char hex
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

### Generate random bytes and a UUID

```doof
import { randomBytes, uuidV4, encodeHex } from "std/crypto"

nonce := randomBytes(16)
requestId := uuidV4()

println(encodeHex(nonce))
println(requestId) // RFC 4122 v4, lowercase
```

### HMAC (SHA-256)

```doof
import { hmacSha256String, encodeHex } from "std/crypto"

mac := hmacSha256String("secret-key", "message") // raw bytes
println(encodeHex(mac))
```

Use `hmacSha256(key: readonly byte[], data: readonly byte[])` when your key is binary; use `hmacSha256String` when you have a UTF-8 key.

### Base64 and Base64Url

```doof
import { encodeBase64, decodeBase64, encodeBase64Url, decodeBase64Url } from "std/crypto"

blob := randomBytes(8)
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

- `sha256(data: readonly byte[]) -> readonly byte[]`
	- Returns the 32-byte SHA-256 digest of `data`.
- `sha256String(text: string) -> readonly byte[]`
	- Hashes the UTF-8 bytes of `text` and returns the 32-byte digest.
- `sha256Hex(data: readonly byte[]) -> string`
	- Returns the lowercase hexadecimal representation of the SHA-256 digest for `data`.
- `sha256HexString(text: string) -> string`
	- Convenience: SHA-256 of `text` (UTF-8) as lowercase hex.
- `streamToSha256(source: Stream<readonly byte[]>) -> readonly byte[]`
	- Incrementally hashes the concatenated bytes from `source` and returns the 32-byte digest.
- `randomBytes(length: int) -> readonly byte[]`
	- Returns cryptographically-strong random bytes of the requested `length`.
- `uuidV4() -> string`
	- Returns a lowercase RFC 4122 version 4 UUID string.
- `encodeHex(data: readonly byte[]) -> string`
	- Converts `data` to lowercase hexadecimal.
- `decodeHex(text: string) -> Result<readonly byte[], string>`
	- Parses hexadecimal (upper- or lower-case) into bytes; returns `Err` with an error message on invalid input.

## Notes

- `encodeHex` always emits lowercase hex.
- `decodeHex` accepts either case but will fail on non-hex characters or odd-length input.
- The random bytes generator uses the platform's cryptographically secure source.
- The UUID generator produces RFC 4122 version 4 UUIDs, which are random except for fixed version and variant bits.