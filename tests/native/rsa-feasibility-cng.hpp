// Windows counterpart: preserve ALL supplied private components in a full blob.
// Not executed on macOS. Compile/link the probe with OpenSSL 3 and bcrypt.lib.
struct CngKey { BCRYPT_ALG_HANDLE provider; BCRYPT_KEY_HANDLE handle; };
using BackendKey = CngKey*;

Bytes unsignedInteger(const Bytes& der, Part part) {
    while (part.size > 1 && der.at(part.start) == 0) { ++part.start; --part.size; }
    return Bytes(der.begin() + part.start, der.begin() + part.start + part.size);
}

BackendKey backendImport(const Bytes& der, bool privateKey) {
    std::vector<Part> parts;
    try {
        size_t offset = 0;
        auto sequence = tlv(der, offset, 0x30);
        if (offset != der.size()) return nullptr;
        parts = integers(der);
        if (sequence.size == 0 || parts.size() != (privateKey ? 9 : 2)) return nullptr;
    } catch (const std::exception&) { return nullptr; }
    size_t first = privateKey ? 1 : 0;
    auto n = unsignedInteger(der, parts[first]);
    auto e = unsignedInteger(der, parts[first + 1]);
    auto p = privateKey ? unsignedInteger(der, parts[4]) : Bytes{};
    auto q = privateKey ? unsignedInteger(der, parts[5]) : Bytes{};
    BCRYPT_RSAKEY_BLOB header{};
    header.Magic = privateKey ? BCRYPT_RSAFULLPRIVATE_MAGIC : BCRYPT_RSAPUBLIC_MAGIC;
    header.BitLength = ULONG(n.size() * 8);
    header.cbPublicExp = ULONG(e.size()); header.cbModulus = ULONG(n.size());
    header.cbPrime1 = ULONG(p.size()); header.cbPrime2 = ULONG(q.size());
    Bytes blob(sizeof(header));
    std::memcpy(blob.data(), &header, sizeof(header));
    auto append = [&](const Bytes& value, size_t width) {
        if (value.size() > width) throw std::runtime_error("CNG width");
        blob.insert(blob.end(), width - value.size(), 0);
        blob.insert(blob.end(), value.begin(), value.end());
    };
    append(e, e.size()); append(n, n.size());
    if (privateKey) {
        append(p, p.size()); append(q, q.size());
        append(unsignedInteger(der, parts[6]), p.size());
        append(unsignedInteger(der, parts[7]), q.size());
        append(unsignedInteger(der, parts[8]), p.size());
        append(unsignedInteger(der, parts[3]), n.size());
    }
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_RSA_ALGORITHM,
        MS_PRIMITIVE_PROVIDER, 0) < 0) throw std::runtime_error("CNG provider");
    BCRYPT_KEY_HANDLE key = nullptr;
    auto status = BCryptImportKeyPair(algorithm, nullptr,
        privateKey ? BCRYPT_RSAFULLPRIVATE_BLOB : BCRYPT_RSAPUBLIC_BLOB,
        &key, blob.data(), ULONG(blob.size()), 0);
    SecureZeroMemory(blob.data(), blob.size());
    if (status < 0) { BCryptCloseAlgorithmProvider(algorithm, 0); return nullptr; }
    return new CngKey{algorithm, key};
}

int backendSign(BackendKey key, const Bytes& message, const Bytes& expected) {
    Bytes digest(32);
    unsigned int length = 0;
    if (EVP_Digest(message.data(), message.size(), digest.data(), &length,
        EVP_sha256(), nullptr) != 1) throw std::runtime_error("SHA256");
    BCRYPT_PKCS1_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM};
    ULONG size = 0;
    if (BCryptSignHash(key->handle, &padding, digest.data(), ULONG(digest.size()),
        nullptr, 0, &size, BCRYPT_PAD_PKCS1) < 0) return -1;
    Bytes signature(size);
    if (BCryptSignHash(key->handle, &padding, digest.data(), ULONG(digest.size()),
        signature.data(), size, &size, BCRYPT_PAD_PKCS1) < 0) return -1;
    signature.resize(size);
    return signature == expected;
}

void backendFree(BackendKey key) {
    BCryptDestroyKey(key->handle); BCryptCloseAlgorithmProvider(key->provider, 0); delete key;
}
// DER export is not part of CNG; roundtrip comparison is an Apple-only probe.
int backendRoundtrip(BackendKey, const Bytes&) { return -1; }

int backendVerify(BackendKey key, const Bytes& message, const Bytes& signature) {
    Bytes digest(32);
    unsigned int length = 0;
    if (EVP_Digest(message.data(), message.size(), digest.data(), &length,
        EVP_sha256(), nullptr) != 1) throw std::runtime_error("SHA256");
    BCRYPT_PKCS1_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM};
    auto status = BCryptVerifySignature(key->handle, &padding, digest.data(), ULONG(digest.size()),
        const_cast<unsigned char*>(signature.data()), ULONG(signature.size()), BCRYPT_PAD_PKCS1);
    return status >= 0;
}
