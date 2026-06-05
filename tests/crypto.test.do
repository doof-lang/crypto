import { Assert } from "std/assert"
import {
    blobStreamToSha256, decodeBase64, decodeBase64Url, decodeHex, encodeBase64,
    encodeBase64Url, encodeHex, hmacSha256, hmacSha256Base64Url,
    hmacSha256Hex, randomBytes,
    SecretBytes, sha1, sha1Hex, sha1HexString, sha1String, sha256, sha256Hex,
    sha256HexString, sha256String, timingSafeEqual, uuidV4, parseJwt,
    verifyJwtHs256,
} from "../index"

class ChunkStream implements Stream<readonly byte[]> {
    chunks: byte[][]
    index: int = 0
    currentValue: readonly byte[] = []

    next(): bool {
        if this.index >= this.chunks.length {
            return false
        }

        chunk := this.chunks[this.index]
        this.index = this.index + 1
        this.currentValue = chunk.buildReadonly()
        return true
    }

    value(): readonly byte[] => this.currentValue
}

function assertBytes(actual: readonly byte[], expected: readonly byte[]): void {
    Assert.equal(actual.length, expected.length)

    for index of 0..<actual.length {
        Assert.equal(actual[index], expected[index])
    }
}

function isFailure<T, E>(result: Result<T, E>): bool {
    return case result {
        _: Success -> false,
        _: Failure -> true
    }
}

export function testEncodeHex(): void {
    payload: readonly byte[] := [0, 1, 15, 16, 171, 255]
    Assert.equal(encodeHex(payload), "00010f10abff")
}

export function testDecodeHex(): void {
    decoded := try! decodeHex("00010F10abff")
    expected: readonly byte[] := [0, 1, 15, 16, 171, 255]
    assertBytes(decoded, expected)
}

export function testDecodeHexRejectsOddLength(): void {
    Assert.isTrue(isFailure(decodeHex("abc")))
}

export function testDecodeHexRejectsInvalidCharacter(): void {
    Assert.isTrue(isFailure(decodeHex("0x")))
}

export function testSha1KnownVectorForEmptyBytes(): void {
    empty: readonly byte[] := []
    Assert.equal(
        sha1Hex(empty),
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    )
}

export function testSha1KnownVectorForString(): void {
    Assert.equal(
        sha1HexString("abc"),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    )
}

export function testSha1StringMatchesByteHash(): void {
    payload: readonly byte[] := [104, 101, 108, 108, 111]
    assertBytes(sha1String("hello"), sha1(payload))
}

export function testSha1Base64WebSocketAcceptVector(): void {
    digest := sha1String("dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
    Assert.equal(encodeBase64(digest), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
}

export function testSha256KnownVectorForEmptyBytes(): void {
    empty: readonly byte[] := []
    Assert.equal(
        sha256Hex(empty),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
}

export function testSha256KnownVectorForString(): void {
    Assert.equal(
        sha256HexString("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
}

export function testSha256StringMatchesByteHash(): void {
    payload: readonly byte[] := [104, 101, 108, 108, 111]
    assertBytes(sha256String("hello"), sha256(payload))
}

export function testStreamToSha256MatchesOneShotHash(): void {
    let stream: Stream<readonly byte[]> = ChunkStream {
        chunks: [
            [104, 101],
            [108],
            [],
            [108, 111],
        ]
    }

    payload: readonly byte[] := [104, 101, 108, 108, 111]
    assertBytes(blobStreamToSha256(stream), sha256(payload))
}

export function testHmacSha256KnownVector(): void {
    key := SecretBytes.steal([107, 101, 121])
    payload: readonly byte[] := [
        84, 104, 101, 32, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119,
        110, 32, 102, 111, 120, 32, 106, 117, 109, 112, 115, 32, 111, 118,
        101, 114, 32, 116, 104, 101, 32, 108, 97, 122, 121, 32, 100, 111,
        103,
    ]

    Assert.equal(
        encodeHex(hmacSha256(key, payload)),
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    )
}

export function testHmacSha256ReturnsRawBytes(): void {
    key := SecretBytes.steal([107, 101, 121])
    payload: readonly byte[] := [
        84, 104, 101, 32, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119,
        110, 32, 102, 111, 120, 32, 106, 117, 109, 112, 115, 32, 111, 118,
        101, 114, 32, 116, 104, 101, 32, 108, 97, 122, 121, 32, 100, 111,
        103,
    ]
    Assert.equal(hmacSha256(key, payload).length, 32)
}

export function testHmacSha256HexHelpers(): void {
    key := SecretBytes.steal([107, 101, 121])
    payload: readonly byte[] := [
        84, 104, 101, 32, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119,
        110, 32, 102, 111, 120, 32, 106, 117, 109, 112, 115, 32, 111, 118,
        101, 114, 32, 116, 104, 101, 32, 108, 97, 122, 121, 32, 100, 111,
        103,
    ]
    expected := "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"

    Assert.equal(hmacSha256Hex(key, payload), expected)
}

export function testHmacSha256Base64Url(): void {
    key := SecretBytes.steal([107, 101, 121])
    payload: readonly byte[] := [100, 97, 116, 97]
    Assert.equal(hmacSha256Base64Url(key, payload), "UDH-PZicbRU3oBP6bnOdojRj_a7DtwE32Cjjas4iG9A")
}

export function testTimingSafeEqual(): void {
    a: readonly byte[] := [1, 2, 3]
    same: readonly byte[] := [1, 2, 3]
    differentValue: readonly byte[] := [1, 2, 4]
    differentLength: readonly byte[] := [1, 2, 3, 0]

    Assert.isTrue(timingSafeEqual(a, same))
    Assert.isFalse(timingSafeEqual(a, differentValue))
    Assert.isFalse(timingSafeEqual(a, differentLength))
}

export function testEncodeBase64(): void {
    payload: readonly byte[] := [104, 101, 108, 108, 111]
    Assert.equal(encodeBase64(payload), "aGVsbG8=")
}

export function testDecodeBase64(): void {
    payload: readonly byte[] := [104, 101, 108, 108, 111]
    assertBytes(try! decodeBase64("aGVsbG8="), payload)
    assertBytes(try! decodeBase64("aGVsbG8"), payload)
}

export function testEncodeBase64Url(): void {
    payload: readonly byte[] := [251, 239, 255]
    Assert.equal(encodeBase64Url(payload), "--__")
}

export function testDecodeBase64Url(): void {
    payload: readonly byte[] := [251, 239, 255]
    assertBytes(try! decodeBase64Url("--__"), payload)
}

export function testDecodeBase64RejectsInvalidCharacter(): void {
    Assert.isTrue(isFailure(decodeBase64("aGVsbG8!")))
}

export function testRandomBytesLength(): void {
    generated := randomBytes(24)
    Assert.equal(generated.length(), 24)
    Assert.equal(generated.bytes().length, 24)
}

export function testRandomBytesZeroLength(): void {
    Assert.equal(randomBytes(0).length(), 0)
}

export function testSecretBytesStealAndBytes(): void {
    secret := SecretBytes.steal([1, 2, 3])
    assertBytes(secret.bytes(), [1, 2, 3])
}

export function testSecretBytesWipe(): void {
    secret := SecretBytes.steal([1, 2, 3])
    secret.wipe()
    assertBytes(secret.bytes(), [0, 0, 0])
}

export function testUuidV4Shape(): void {
    uuid := uuidV4()
    Assert.equal(uuid.length, 36)
    Assert.equal(string(uuid.charAt(8)), "-")
    Assert.equal(string(uuid.charAt(13)), "-")
    Assert.equal(string(uuid.charAt(18)), "-")
    Assert.equal(string(uuid.charAt(23)), "-")
    Assert.equal(string(uuid.charAt(14)), "4")

    variant := string(uuid.charAt(19))
    Assert.isTrue(variant == "8" || variant == "9" || variant == "a" || variant == "b")

    compact := uuid.replaceAll("-", "")
    Assert.equal(compact.length, 32)
    Assert.equal((try! decodeHex(compact)).length, 16)
}

export function testParseJwt(): void {
    token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"  
    jwt := try! parseJwt(token)
    alg := jwt.header.get("alg") as string else {
        panic("Missing or malformed alg in header")
    }
    sub := jwt.claims.get("sub") as string else {
        panic("Missing or malformed sub in claims")
    }
    name := jwt.claims.get("name") as string else {
        panic("Missing or malformed name in claims")
    }
    iat := jwt.claims.get("iat") as long else {
        panic("Missing or malformed iat in claims")
    }
    Assert.equal(alg, "HS256")
    Assert.equal(sub, "1234567890")
    Assert.equal(name, "John Doe")
    Assert.equal(iat, 1516239022)
}  

export function testVerifyJwtHs256(): void {
    token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    key := SecretBytes.steal([
        121, 111, 117, 114, 45, 50, 53, 54, 45, 98, 105, 116, 45,
        115, 101, 99, 114, 101, 116,
    ])
    jwt := try! verifyJwtHs256(token, key)
    name := jwt.claims.get("name") as string else {
        panic("Missing or malformed name in claims")
    }

    Assert.equal(name, "John Doe")
}

export function testVerifyJwtHs256Bytes(): void {
    token := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.ZjfNiRshnSbF4iYwt1MtAQat8zRdUCKNyfXJdsfM8b0"
    key := SecretBytes.steal([115, 101, 99, 114, 101, 116])
    jwt := try! verifyJwtHs256(token, key)
    sub := jwt.claims.get("sub") as string else {
        panic("Missing or malformed sub in claims")
    }

    Assert.equal(sub, "123")
}

export function testVerifyJwtHs256RejectsInvalidSignature(): void {
    token := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.ZjfNiRshnSbF4iYwt1MtAQat8zRdUCKNyfXJdsfM8b0"
    key := SecretBytes.steal([119, 114, 111, 110, 103, 45, 115, 101, 99, 114, 101, 116])
    Assert.isTrue(isFailure(verifyJwtHs256(token, key)))
}

export function testVerifyJwtHs256RejectsAlgorithmMismatch(): void {
    token := "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ."
    key := SecretBytes.steal([115, 101, 99, 114, 101, 116])
    Assert.isTrue(isFailure(verifyJwtHs256(token, key)))
}
