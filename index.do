import { parseJsonValue } from "std/json"
import { BlobReader } from "std/blob"

export import function sha256(data: readonly byte[]): readonly byte[] from "doof_crypto.hpp" as doof_crypto::sha256_bytes
export import function sha256String(text: string): readonly byte[] from "doof_crypto.hpp" as doof_crypto::sha256_utf8
export function sha256Hex(data: readonly byte[]): string => encodeHex(sha256(data))
export function sha256HexString(text: string): string => encodeHex(sha256String(text))
export import function blobStreamToSha256(source: Stream<readonly byte[]>): readonly byte[] from "doof_crypto.hpp" as doof_crypto::stream_to_sha256

export import function hmacSha256(key: readonly byte[], data: readonly byte[]): readonly byte[] from "doof_crypto.hpp" as doof_crypto::hmac_sha256
export import function hmacSha256String(key: string, text: string): readonly byte[] from "doof_crypto.hpp" as doof_crypto::hmac_sha256_utf8

export import function encodeHex(data: readonly byte[]): string from "doof_crypto.hpp" as doof_crypto::encode_hex
export import function decodeHex(text: string): Result<readonly byte[], string> from "doof_crypto.hpp" as doof_crypto::decode_hex
export import function encodeBase64(data: readonly byte[]): string from "doof_crypto.hpp" as doof_crypto::encode_base64
export import function decodeBase64(text: string): Result<readonly byte[], string> from "doof_crypto.hpp" as doof_crypto::decode_base64
export import function encodeBase64Url(data: readonly byte[]): string from "doof_crypto.hpp" as doof_crypto::encode_base64_url
export import function decodeBase64Url(text: string): Result<readonly byte[], string> from "doof_crypto.hpp" as doof_crypto::decode_base64_url

export import function randomBytes(length: int): readonly byte[] from "doof_crypto.hpp" as doof_crypto::random_bytes
export import function uuidV4(): string from "doof_crypto.hpp" as doof_crypto::uuid_v4

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