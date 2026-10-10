import { SecretBytes } from "./index"

export enum CryptoErrorKind {
    InvalidKey, UnsupportedKeyType, EncryptedPrivateKey,
    KeyPolicyRejected, CapabilityUnavailable, BackendFailure
}

export class CryptoError {
    kind: CryptoErrorKind
    message: string
}

import class NativeRsaKey from "doof_rsa.hpp" as doof_crypto::NativeRsaKey {
    static fromPrivatePem(pem: SecretBytes): Result<NativeRsaKey, int>
    static fromPublicPem(pem: readonly byte[]): Result<NativeRsaKey, int>
    sign(data: readonly byte[]): Result<readonly byte[], int>
    verify(data: readonly byte[], signature: readonly byte[]): Result<bool, int>
}

function cryptoError(code: int): CryptoError {
    return case code {
        0 -> CryptoError { kind: .InvalidKey, message: "Invalid RSA key encoding or unusable key" },
        1 -> CryptoError { kind: .UnsupportedKeyType, message: "Only unrestricted RSA keys are supported" },
        2 -> CryptoError { kind: .EncryptedPrivateKey, message: "Encrypted private keys are unsupported" },
        3 -> CryptoError { kind: .KeyPolicyRejected, message: "RSA key exceeds input limits or violates key policy" },
        4 -> CryptoError { kind: .CapabilityUnavailable, message: "RSA signing backend is unavailable on this target" },
        _ -> CryptoError { kind: .BackendFailure, message: "RSA backend operation failed" }
    }
}

export class RsaPrivateKey {
    private key: NativeRsaKey

    static constructor(pem: SecretBytes): Result<RsaPrivateKey, CryptoError> {
        key := NativeRsaKey.fromPrivatePem(pem) else code { return { error: cryptoError(code) } }
        return { value: RsaPrivateKey { key } }
    }

    static fromPem(pem: SecretBytes): Result<RsaPrivateKey, CryptoError> => RsaPrivateKey(pem)

    signSha256Pkcs1v15(data: readonly byte[]): Result<readonly byte[], CryptoError> {
        value := this.key.sign(data) else code { return { error: cryptoError(code) } }
        return { value }
    }
}

export class RsaPublicKey {
    private key: NativeRsaKey

    static constructor(pem: readonly byte[]): Result<RsaPublicKey, CryptoError> {
        key := NativeRsaKey.fromPublicPem(pem) else code { return { error: cryptoError(code) } }
        return { value: RsaPublicKey { key } }
    }

    static fromPem(pem: readonly byte[]): Result<RsaPublicKey, CryptoError> => RsaPublicKey(pem)

    verifySha256Pkcs1v15(data: readonly byte[], signature: readonly byte[]): Result<bool, CryptoError> {
        value := this.key.verify(data, signature) else code { return { error: cryptoError(code) } }
        return { value }
    }
}
