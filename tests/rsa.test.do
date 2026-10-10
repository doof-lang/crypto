import { Assert } from "std/assert"
import { BlobBuilder } from "std/blob"
import { RsaPrivateKey, RsaPublicKey, CryptoError, CryptoErrorKind, SecretBytes, decodeBase64, encodeBase64 } from "../index"
import { rsa2048private, rsa2048pkcs8, rsa2048public, rsa2048pkcs1public, rsa2048Signature,
    rsa3072private, rsa3072pkcs8, rsa3072public, rsa3072pkcs1public, rsa3072Signature,
    rsa4096private, rsa4096pkcs8, rsa4096public, rsa4096pkcs1public, rsa4096Signature,
    rsasmallPublic, rsaecPublic, rsapssPublic, rsaotherPublic } from "./rsa-fixtures"

function bytes(text: string): readonly byte[] {
    builder := BlobBuilder()
    builder.writeString(text)
    return builder.build()
}

function unavailable(): bool {
    return case RsaPublicKey.fromPem(bytes(rsa2048public)) {
        _: Success -> false,
        f: Failure -> f.error.kind == .CapabilityUnavailable
    }
}

function expectError<T>(result: Result<T, CryptoError>, kind: CryptoErrorKind): none {
    case result {
        _: Success -> Assert.fail("Expected import failure"),
        f: Failure -> Assert.equal(f.error.kind, kind)
    }
}

function interoperability(privatePem: string, pkcs8: string, publicPem: string, pkcs1: string, signature: string): none {
    if unavailable() {
        expectError(RsaPrivateKey.fromPem(SecretBytes.steal(bytes(privatePem))), .CapabilityUnavailable)
        return
    }
    source := SecretBytes.steal(bytes(privatePem))
    privateKey := RsaPrivateKey.fromPem(source)!
    source.wipe()
    publicKey := RsaPublicKey.fromPem(bytes(publicPem))!
    message := bytes("Doof RSA interoperability fixture")
    actual := privateKey.signSha256Pkcs1v15(message)!
    Assert.equal(encodeBase64(actual), signature)
    Assert.isTrue(publicKey.verifySha256Pkcs1v15(message, decodeBase64(signature)!)!)
    otherPrivate := RsaPrivateKey.fromPem(SecretBytes.steal(bytes(pkcs8)))!
    otherPublic := RsaPublicKey.fromPem(bytes(pkcs1))!
    Assert.arrayEqual(otherPrivate.signSha256Pkcs1v15(message)!, actual)
    Assert.isTrue(otherPublic.verifySha256Pkcs1v15(message, actual)!)
    payloads: readonly byte[][] := [[], [0], [0, 255, 128, 1, 0, 42]]
    for payload of payloads {
        sig := privateKey.signSha256Pkcs1v15(payload)!
        Assert.isTrue(publicKey.verifySha256Pkcs1v15(payload, sig)!)
    }
    utf8 := bytes("こんにちは 🦆")
    Assert.isTrue(publicKey.verifySha256Pkcs1v15(utf8, privateKey.signSha256Pkcs1v15(utf8)!)!)
    Assert.isFalse(publicKey.verifySha256Pkcs1v15(bytes("modified"), actual)!)
    Assert.isFalse(publicKey.verifySha256Pkcs1v15(message, [])!)
    bad := BlobBuilder()
    bad.writeBytes(actual)
    bad.writeByte(0)
    Assert.isFalse(publicKey.verifySha256Pkcs1v15(message, bad.build())!)
    corrupt: byte[] := []
    for value of actual { corrupt.push(0) }
    Assert.isFalse(publicKey.verifySha256Pkcs1v15(message, corrupt.drainToReadonly())!)
}

export function testRsa2048Interoperability(): none { interoperability(rsa2048private, rsa2048pkcs8, rsa2048public, rsa2048pkcs1public, rsa2048Signature) }
export function testRsa3072Interoperability(): none { interoperability(rsa3072private, rsa3072pkcs8, rsa3072public, rsa3072pkcs1public, rsa3072Signature) }
export function testRsa4096Interoperability(): none { interoperability(rsa4096private, rsa4096pkcs8, rsa4096public, rsa4096pkcs1public, rsa4096Signature) }

export function testRsaWrongPublicKey(): none {
    if unavailable() { return }
    priv := RsaPrivateKey.fromPem(SecretBytes.steal(bytes(rsa2048private)))!
    pub := RsaPublicKey.fromPem(bytes(rsaotherPublic))!
    Assert.isFalse(pub.verifySha256Pkcs1v15([], priv.signSha256Pkcs1v15([])!)!)
}

export function testRsaStrictPemEnvelope(): none {
    expectError(RsaPublicKey.fromPem([]), .InvalidKey)
    expectError(RsaPublicKey.fromPem(bytes("garbage")), .InvalidKey)
    expectError(RsaPublicKey.fromPem(bytes(rsa2048public + rsa2048public)), .InvalidKey)
    expectError(RsaPublicKey.fromPem(bytes(rsa2048public + "trailing")), .InvalidKey)
    expectError(RsaPublicKey.fromPem(bytes("-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----")), .InvalidKey)
    expectError(RsaPublicKey.fromPem(bytes("-----BEGIN PUBLIC KEY-----\nMAA=\n-----END PUBLIC KEY-----")), .InvalidKey)
    if !unavailable() { key := RsaPublicKey.fromPem(bytes(" \t\n" + rsa2048public + "\r\n "))! }
}

export function testRsaEncryptedAndUnsupported(): none {
    expectError(RsaPrivateKey.fromPem(SecretBytes.steal(bytes("-----BEGIN ENCRYPTED PRIVATE KEY-----\nMAA=\n-----END ENCRYPTED PRIVATE KEY-----"))), .EncryptedPrivateKey)
    expectError(RsaPrivateKey.fromPem(SecretBytes.steal(bytes("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nMAA=\n-----END RSA PRIVATE KEY-----"))), .EncryptedPrivateKey)
    expectError(RsaPublicKey.fromPem(bytes("-----BEGIN EC PUBLIC KEY-----\nMAA=\n-----END EC PUBLIC KEY-----")), .UnsupportedKeyType)
}

export function testRsaInputBound(): none {
    builder := BlobBuilder()
    for i of 0..<32769 { builder.writeByte(32) }
    expectError(RsaPublicKey.fromPem(builder.build()), .KeyPolicyRejected)
}

export function testRsaAlgorithmAndSizePolicy(): none {
    expectError(RsaPublicKey.fromPem(bytes(rsasmallPublic)), .KeyPolicyRejected)
    expectError(RsaPublicKey.fromPem(bytes(rsaecPublic)), .UnsupportedKeyType)
    expectError(RsaPublicKey.fromPem(bytes(rsapssPublic)), .UnsupportedKeyType)
}

export function testRsaRejectsTrailingAndTruncatedDer(): none {
    let body = ""
    for line of rsa2048pkcs1public.split("\n") {
        if !line.startsWith("-----") { body = body + line }
    }
    der := decodeBase64(body)!
    trailing := BlobBuilder()
    trailing.writeBytes(der)
    trailing.writeByte(0)
    expectError(RsaPublicKey.fromPem(bytes("-----BEGIN RSA PUBLIC KEY-----\n" + encodeBase64(trailing.build()) + "\n-----END RSA PUBLIC KEY-----")), .InvalidKey)
    truncated := BlobBuilder()
    for i of 0..<der.length - 1 { truncated.writeByte(der[i]) }
    expectError(RsaPublicKey.fromPem(bytes("-----BEGIN RSA PUBLIC KEY-----\n" + encodeBase64(truncated.build()) + "\n-----END RSA PUBLIC KEY-----")), .InvalidKey)
}
