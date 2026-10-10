// Disposable native experiment, not production RSA code. Uses OpenSSL as oracle.
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <Security/Security.h>
#endif
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using Bytes = std::vector<unsigned char>;
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Context = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using Digest = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
struct Part { size_t start, size; };

// Locate INTEGER content without changing DER lengths or signs during mutations.
Part tlv(const Bytes& data, size_t& offset, unsigned char tag) {
    if (offset >= data.size() || data.at(offset++) != tag) throw std::runtime_error("tag");
    size_t size = data.at(offset++);
    if (size & 128) {
        size_t count = size & 127;
        size = 0;
        if (count == 0 || count > sizeof(size_t)) throw std::runtime_error("length");
        while (count--) size = (size << 8) | data.at(offset++);
    }
    if (size > data.size() - offset) throw std::runtime_error("bounds");
    Part result{offset, size};
    offset += size;
    return result;
}

std::vector<Part> integers(const Bytes& data) {
    size_t offset = 0;
    auto sequence = tlv(data, offset, 0x30);
    offset = sequence.start;
    std::vector<Part> parts;
    while (offset < sequence.start + sequence.size) parts.push_back(tlv(data, offset, 2));
    return parts;
}

Key decode(const Bytes& der) {
    const unsigned char* cursor = der.data();
    return Key(d2i_PrivateKey(EVP_PKEY_RSA, nullptr, &cursor, long(der.size())), EVP_PKEY_free);
}

int validate(const Bytes& der) {
    ERR_clear_error();
    auto key = decode(der);
    if (!key) return 0;
    Context context(EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr), EVP_PKEY_CTX_free);
    if (!context) throw std::runtime_error("context");
    return EVP_PKEY_check(context.get());
}

Bytes oracleSignature(EVP_PKEY* key, const Bytes& message) {
    Digest context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    EVP_PKEY_CTX* signing = nullptr;
    if (!context || EVP_DigestSignInit(context.get(), &signing, EVP_sha256(), nullptr, key) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(signing, RSA_PKCS1_PADDING) != 1)
        throw std::runtime_error("sign initialization");
    size_t size = 0;
    if (EVP_DigestSign(context.get(), nullptr, &size, message.data(), message.size()) != 1)
        throw std::runtime_error("sign size");
    Bytes result(size);
    if (EVP_DigestSign(context.get(), result.data(), &size, message.data(), message.size()) != 1)
        throw std::runtime_error("sign");
    result.resize(size);
    return result;
}

#ifdef _WIN32
#include "rsa-feasibility-cng.hpp"
#else
#include "rsa-feasibility-apple.hpp"
#endif

void probe(const char* label, int bits, const Bytes& der, const Bytes& message, const Bytes& expected) {
    int evp = validate(der);
    auto key = backendImport(der, true);
    int sign = key ? backendSign(key, message, expected) : -2;
    std::printf("%d,%s,%d,%d,%d,%d\n", bits, label, evp, key != nullptr, sign,
        key ? backendRoundtrip(key, der) : -2);
    std::fflush(stdout);
    if (key) backendFree(key);
    if ((std::string(label) == "valid") && (evp != 1 || sign != 1))
        throw std::runtime_error("baseline failed");
}

void publicProbe(int bits, EVP_PKEY* original, const Bytes& message, const Bytes& signature) {
    int size = i2d_PublicKey(original, nullptr);
    if (size <= 0) throw std::runtime_error("public DER encoding");
    Bytes der(size);
    auto cursor = der.data();
    i2d_PublicKey(original, &cursor);
    auto parts = integers(der);
    if (parts.size() != 2) throw std::runtime_error("public format");
    for (const char* name : {"public-valid", "public-even-n", "public-e-65536", "public-e-65538"}) {
        auto input = der;
        if (std::string(name) == "public-even-n") input.at(parts[0].start + parts[0].size - 1) &= 0xfe;
        if (std::string(name) == "public-e-65536" || std::string(name) == "public-e-65538") {
            // Keep canonical INTEGER encoding: same length, value 65536 or 65538.
            input.at(parts[1].start + parts[1].size - 1) = std::string(name) == "public-e-65536" ? 0 : 2;
        }
        const unsigned char* read = input.data();
        Key key(d2i_PublicKey(EVP_PKEY_RSA, nullptr, &read, input.size()), EVP_PKEY_free);
        Context context(key ? EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr) : nullptr, EVP_PKEY_CTX_free);
        auto native = backendImport(input, false);
        std::printf("%d,%s,%d,%d,%d,%d\n", bits, name,
            context ? EVP_PKEY_public_check(context.get()) : 0, native != nullptr,
            native ? backendVerify(native, message, signature) : -2,
            native ? backendRoundtrip(native, input) : -2);
        if (std::string(name) == "public-valid" && (!native || backendVerify(native, message, signature) != 1))
            throw std::runtime_error("public baseline");
        if (native) backendFree(native);
    }
}

int main(int argc, char** argv) {
    std::printf("OpenSSL %s\n", OpenSSL_version(OPENSSL_VERSION));
    std::puts("bits,case,evp_valid,backend_imported,signature_matches_original,roundtrip_identical");
    const Bytes message{'D','o','o','f',0,255,128,10};
    for (int bits : {2048, 3072, 4096, 8192}) {
        if (argc > 1 && bits != std::stoi(argv[1])) continue;
        Context generation(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), EVP_PKEY_CTX_free);
        EVP_PKEY* raw = nullptr;
        if (!generation || EVP_PKEY_keygen_init(generation.get()) != 1 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(generation.get(), bits) != 1 ||
            EVP_PKEY_keygen(generation.get(), &raw) != 1) throw std::runtime_error("key generation");
        Key key(raw, EVP_PKEY_free);
        int size = i2d_PrivateKey(key.get(), nullptr);
        if (size <= 0) throw std::runtime_error("DER encoding");
        Bytes der(size);
        unsigned char* cursor = der.data();
        i2d_PrivateKey(key.get(), &cursor);
        auto expected = oracleSignature(key.get(), message);
        publicProbe(bits, key.get(), message, expected);
        probe("valid", bits, der, message, expected);
        auto apple = backendImport(der, true);
        for (const Bytes& payload : {Bytes{}, Bytes{'h','e','l','l','o'}, message})
            if (backendSign(apple, payload, oracleSignature(key.get(), payload)) != 1)
                throw std::runtime_error("message parity");
        backendFree(apple);
        auto parts = integers(der);
        if (parts.size() != 9) throw std::runtime_error("unexpected PKCS1 key");
        const char* names[] = {"version", "n", "e", "d", "p", "q", "dP", "dQ", "qInv"};
        for (size_t index = 1; index < parts.size(); ++index) {
            auto mutated = der;
            mutated.at(parts[index].start + parts[index].size - 1) ^= 2;
            probe(names[index], bits, mutated, message, expected);
            if (validate(mutated) == 1) throw std::runtime_error("oracle accepted mutation");
        }
        auto truncated = der; truncated.pop_back();
        probe("truncated", bits, truncated, message, expected);
        auto trailing = der; trailing.push_back(0);
        probe("trailing-zero", bits, trailing, message, expected);
    }
}
