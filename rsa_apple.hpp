#pragma once
#include <Security/Security.h>
namespace doof_crypto {
template<typename T> struct CfOwned {
    T value=nullptr;
    explicit CfOwned(T v=nullptr):value(v){}
    ~CfOwned(){if(value)CFRelease(value);}
    CfOwned(const CfOwned&)=delete;
};
struct NativeRsaKey::Backend {
    CfOwned<SecKeyRef> key, publicKey;
    static std::unique_ptr<Backend> create(const rsa::Parsed& parsed,bool priv) {
        auto result=std::make_unique<Backend>();
        CfOwned<CFDataRef> data(CFDataCreateWithBytesNoCopy(nullptr,parsed.der.bytes.data(),parsed.der.bytes.size(),kCFAllocatorNull));
        const void* names[]={kSecAttrKeyType,kSecAttrKeyClass};
        const void* values[]={kSecAttrKeyTypeRSA,priv?kSecAttrKeyClassPrivate:kSecAttrKeyClassPublic};
        CfOwned<CFDictionaryRef> attrs(CFDictionaryCreate(nullptr,names,values,2,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks));
        if(!data.value||!attrs.value)throw rsa::Error{5};
        CfOwned<CFErrorRef> error;
        result->key.value=SecKeyCreateWithData(data.value,attrs.value,&error.value);
        if(!result->key.value)throw rsa::Error{0};
        result->publicKey.value=priv?SecKeyCopyPublicKey(result->key.value):(SecKeyRef)CFRetain(result->key.value);
        if(!result->publicKey.value)throw rsa::Error{5};
        return result;
    }
    rsa::Bytes sign(const rsa::Bytes& message) {
        CfOwned<CFDataRef> data(CFDataCreate(nullptr,message.data(),message.size()));
        CfOwned<CFErrorRef> error;
        if(!data.value)throw rsa::Error{5};
        CfOwned<CFDataRef> sig(SecKeyCreateSignature(key.value,kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,data.value,&error.value));
        if(!sig.value)throw rsa::Error{5};
        return rsa::Bytes(CFDataGetBytePtr(sig.value),CFDataGetBytePtr(sig.value)+CFDataGetLength(sig.value));
    }
    bool verify(const rsa::Bytes& message,const rsa::Bytes& signature) {
        CfOwned<CFDataRef> data(CFDataCreate(nullptr,message.data(),message.size())),sig(CFDataCreate(nullptr,signature.data(),signature.size()));
        if(!data.value||!sig.value)throw rsa::Error{5};
        CfOwned<CFErrorRef> error;
        bool ok=SecKeyVerifySignature(publicKey.value,kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,data.value,sig.value,&error.value);
        if(ok)return true;
        if(error.value&&CFEqual(CFErrorGetDomain(error.value),kCFErrorDomainOSStatus)&&CFErrorGetCode(error.value)==errSecVerifyFailed)return false;
        throw rsa::Error{5};
    }
};
}
