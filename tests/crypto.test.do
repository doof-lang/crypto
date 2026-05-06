import { Assert } from "std/assert"
import {
    blobStreamToSha256, decodeBase64, decodeBase64Url, decodeHex, encodeBase64,
    encodeBase64Url, encodeHex, hmacSha256, hmacSha256String, randomBytes,
    sha256, sha256Hex, sha256HexString, sha256String, uuidV4, parseJwt,
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
    Assert.equal(
        encodeHex(hmacSha256String("key", "The quick brown fox jumps over the lazy dog")),
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    )
}

export function testHmacSha256BytesMatchesStringVariant(): void {
    key: readonly byte[] := [107, 101, 121]
    payload: readonly byte[] := [
        84, 104, 101, 32, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119,
        110, 32, 102, 111, 120, 32, 106, 117, 109, 112, 115, 32, 111, 118,
        101, 114, 32, 116, 104, 101, 32, 108, 97, 122, 121, 32, 100, 111,
        103,
    ]
    assertBytes(hmacSha256(key, payload), hmacSha256String("key", "The quick brown fox jumps over the lazy dog"))
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
    Assert.equal(generated.length, 24)
}

export function testRandomBytesZeroLength(): void {
    Assert.equal(randomBytes(0).length, 0)
}

export function testUuidV4Shape(): void {
    uuid := uuidV4()
    Assert.equal(uuid.length, 36)
    Assert.equal(uuid.charAt(8), "-")
    Assert.equal(uuid.charAt(13), "-")
    Assert.equal(uuid.charAt(18), "-")
    Assert.equal(uuid.charAt(23), "-")
    Assert.equal(uuid.charAt(14), "4")

    variant := uuid.charAt(19)
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