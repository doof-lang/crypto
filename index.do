import { parseJsonValue } from "std/json"
import { BlobBuilder, BlobReader } from "std/blob"

export import class SecretBytes from "doof_crypto.hpp" as doof_crypto::SecretBytes {
    isolated static random(length: int): SecretBytes
    isolated static steal(data: readonly byte[]): SecretBytes
    isolated wipe(): void
    isolated bytes(): readonly byte[]
    isolated length(): int
}

export import isolated function sha1(data: readonly byte[]): readonly byte[] from "doof_crypto.hpp" as doof_crypto::sha1_bytes
export import isolated function sha1String(text: string): readonly byte[] from "doof_crypto.hpp" as doof_crypto::sha1_utf8
export function sha1Hex(data: readonly byte[]): string => encodeHex(sha1(data))
export function sha1HexString(text: string): string => encodeHex(sha1String(text))

export import isolated function sha256(data: readonly byte[]): readonly byte[] from "doof_crypto.hpp" as doof_crypto::sha256_bytes
export import isolated function sha256String(text: string): readonly byte[] from "doof_crypto.hpp" as doof_crypto::sha256_utf8
export function sha256Hex(data: readonly byte[]): string => encodeHex(sha256(data))
export function sha256HexString(text: string): string => encodeHex(sha256String(text))
export import isolated function blobStreamToSha256(source: Stream<readonly byte[]>): readonly byte[] from "doof_crypto.hpp" as doof_crypto::stream_to_sha256

export import isolated function hmacSha256(key: SecretBytes, data: readonly byte[]): readonly byte[] from "doof_crypto.hpp" as doof_crypto::hmac_sha256
export function hmacSha256Hex(key: SecretBytes, data: readonly byte[]): string => encodeHex(hmacSha256(key, data))
export function hmacSha256Base64Url(key: SecretBytes, data: readonly byte[]): string => encodeBase64Url(hmacSha256(key, data))
export import isolated function timingSafeEqual(a: readonly byte[], b: readonly byte[]): bool from "doof_crypto.hpp" as doof_crypto::timing_safe_equal

export import isolated function encodeHex(data: readonly byte[]): string from "doof_crypto.hpp" as doof_crypto::encode_hex
export import isolated function decodeHex(text: string): Result<readonly byte[], string> from "doof_crypto.hpp" as doof_crypto::decode_hex
export import isolated function encodeBase64(data: readonly byte[]): string from "doof_crypto.hpp" as doof_crypto::encode_base64
export import isolated function decodeBase64(text: string): Result<readonly byte[], string> from "doof_crypto.hpp" as doof_crypto::decode_base64
export import isolated function encodeBase64Url(data: readonly byte[]): string from "doof_crypto.hpp" as doof_crypto::encode_base64_url
export import isolated function decodeBase64Url(text: string): Result<readonly byte[], string> from "doof_crypto.hpp" as doof_crypto::decode_base64_url

export function randomBytes(length: int): SecretBytes => SecretBytes.random(length)
export import isolated function uuidV4(): string from "doof_crypto.hpp" as doof_crypto::uuid_v4

export class Jwt {
    readonly header: readonly Map<string, JsonValue>
    readonly claims: readonly Map<string, JsonValue>
    readonly signedContent: string
    readonly signature: byte[]
}

export enum JwtError {
    MalformedToken,
    InvalidHeader,
    InvalidPayload,
    AlgorithmMismatch,
    SignatureInvalid,
}

export function decodeBase64UrlToString(text: string): Result<string, string> {
    blob := decodeBase64Url(text) else {
        return { error: "Invalid Base64Url string" }
    }
    reader := BlobReader(blob)
    return { value: reader.readString(reader.length()) }
}

function stringToBytes(text: string): readonly byte[] {
    builder := BlobBuilder()
    builder.writeString(text)
    return builder.build()
}

export function parseJwt(token: string): Result<Jwt, JwtError> {
    parts := token.split(".")
    if parts.length != 3 {
        return { error: .MalformedToken }
    }

    headerJson := decodeBase64UrlToString(parts[0]) else {
        return { error: .InvalidHeader }
    }

    claimsJson := decodeBase64UrlToString(parts[1]) else {
        return { error: .InvalidPayload }
    }

    headerJsonValue := parseJsonValue(headerJson) else {
        return { error: .InvalidHeader }
    }
    
    claimsJsonValue := parseJsonValue(claimsJson) else {
        return { error: .InvalidPayload }
    }
    signature := decodeBase64Url(parts[2]) else {
        return { error: .InvalidPayload }
    }

    header := headerJsonValue as readonly Map<string, JsonValue> else {
        return { error: .InvalidHeader }
    }

    claims := claimsJsonValue as readonly Map<string, JsonValue> else {
        return { error: .InvalidPayload }
    }

    return {
        value: {
            header,
            claims,
            signedContent: parts[0] + "." + parts[1],
            signature
        }
    }

}

export function verifyJwtHs256(token: string, key: SecretBytes): Result<Jwt, JwtError> {
    jwt := parseJwt(token) else {
        return { error: jwt.error }
    }

    alg := jwt.header.get("alg") as string else {
        return { error: .AlgorithmMismatch }
    }
    if alg != "HS256" {
        return { error: .AlgorithmMismatch }
    }

    expectedSignature := hmacSha256(key, stringToBytes(jwt.signedContent))
    if !timingSafeEqual(jwt.signature, expectedSignature) {
        return { error: .SignatureInvalid }
    }

    return { value: jwt }
}
