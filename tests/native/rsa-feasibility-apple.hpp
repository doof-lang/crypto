using BackendKey = SecKeyRef;

BackendKey backendImport(const Bytes& der, bool privateKey) {
    auto data = CFDataCreate(nullptr, der.data(), der.size());
    const void* keys[] = {kSecAttrKeyType, kSecAttrKeyClass};
    const void* values[] = {kSecAttrKeyTypeRSA, privateKey ? kSecAttrKeyClassPrivate : kSecAttrKeyClassPublic};
    auto attributes = CFDictionaryCreate(nullptr, keys, values, 2,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFErrorRef error = nullptr;
    auto key = SecKeyCreateWithData(data, attributes, &error);
    if (error) CFRelease(error);
    CFRelease(attributes);
    CFRelease(data);
    return key;
}

// Test whether signing catches malformed imported private components.
int backendSign(BackendKey key, const Bytes& message, const Bytes& expected) {
    auto data = CFDataCreate(nullptr, message.data(), message.size());
    CFErrorRef error = nullptr;
    auto signature = SecKeyCreateSignature(key,
        kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256, data, &error);
    int result = -1;
    if (signature) {
        result = CFDataGetLength(signature) == long(expected.size()) &&
            std::equal(expected.begin(), expected.end(), CFDataGetBytePtr(signature));
        CFRelease(signature);
    }
    if (error) CFRelease(error);
    CFRelease(data);
    return result;
}

int backendVerify(BackendKey key, const Bytes& message, const Bytes& signature) {
    auto data = CFDataCreate(nullptr, message.data(), message.size());
    auto sig = CFDataCreate(nullptr, signature.data(), signature.size());
    CFErrorRef error = nullptr;
    int result = SecKeyVerifySignature(key,
        kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256, data, sig, &error);
    if (error) CFRelease(error);
    CFRelease(data); CFRelease(sig);
    return result;
}

void backendFree(BackendKey key) { CFRelease(key); }

int backendRoundtrip(BackendKey key, const Bytes& imported) {
    CFErrorRef error = nullptr;
    auto der = SecKeyCopyExternalRepresentation(key, &error);
    int same = -1;
    if (der) {
        same = CFDataGetLength(der) == long(imported.size()) &&
            std::equal(imported.begin(), imported.end(), CFDataGetBytePtr(der));
        CFRelease(der);
    }
    if (error) CFRelease(error);
    return same;
}
