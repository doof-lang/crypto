#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <cstring>
namespace doof_crypto {
struct NativeRsaKey::Backend {
    BCRYPT_ALG_HANDLE provider=nullptr;BCRYPT_KEY_HANDLE key=nullptr;
    ~Backend(){if(key)BCryptDestroyKey(key);
    if(provider)BCryptCloseAlgorithmProvider(provider,0);}
    static std::unique_ptr<Backend> create(const rsa::Parsed& parsed,bool priv) {
        auto result=std::make_unique<Backend>();auto& i=parsed.integers;
        BCRYPT_RSAKEY_BLOB h{};h.Magic=priv?BCRYPT_RSAFULLPRIVATE_MAGIC:BCRYPT_RSAPUBLIC_MAGIC;
        h.BitLength=ULONG(parsed.bits);h.cbPublicExp=ULONG(i[1].n);h.cbModulus=ULONG(i[0].n);
        if(priv){h.cbPrime1=ULONG(i[3].n);h.cbPrime2=ULONG(i[4].n);}
        rsa::SecretBuffer blob;blob.bytes.resize(sizeof(h));std::memcpy(blob.bytes.data(),&h,sizeof(h));
        auto append=[&](rsa::View v,size_t width){if(v.n>width)throw rsa::Error{0};blob.bytes.insert(blob.bytes.end(),width-v.n,0);blob.bytes.insert(blob.bytes.end(),v.p,v.p+v.n);};
        append(i[1],i[1].n);append(i[0],i[0].n);
        if(priv){append(i[3],i[3].n);append(i[4],i[4].n);append(i[5],i[3].n);append(i[6],i[4].n);append(i[7],i[3].n);append(i[2],i[0].n);}
        if(BCryptOpenAlgorithmProvider(&result->provider,BCRYPT_RSA_ALGORITHM,MS_PRIMITIVE_PROVIDER,0)<0)throw rsa::Error{5};
        if(BCryptImportKeyPair(result->provider,nullptr,priv?BCRYPT_RSAFULLPRIVATE_BLOB:BCRYPT_RSAPUBLIC_BLOB,&result->key,blob.bytes.data(),ULONG(blob.bytes.size()),0)<0)throw rsa::Error{0};
        return result;
    }
    rsa::Bytes digest(const rsa::Bytes& message){return *sha256_bytes(std::make_shared<rsa::Bytes>(message));}
    rsa::Bytes sign(const rsa::Bytes& message) {
        auto hash=digest(message);BCRYPT_PKCS1_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM};ULONG size=0;
        if(BCryptSignHash(key,&padding,hash.data(),ULONG(hash.size()),nullptr,0,&size,BCRYPT_PAD_PKCS1)<0)throw rsa::Error{5};
        rsa::Bytes sig(size);
        if(BCryptSignHash(key,&padding,hash.data(),ULONG(hash.size()),sig.data(),size,&size,BCRYPT_PAD_PKCS1)<0)throw rsa::Error{5};
        sig.resize(size);return sig;
    }
    bool verify(const rsa::Bytes& message,const rsa::Bytes& signature) {
        auto hash=digest(message);BCRYPT_PKCS1_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM};
        auto status=BCryptVerifySignature(key,&padding,hash.data(),ULONG(hash.size()),const_cast<uint8_t*>(signature.data()),ULONG(signature.size()),BCRYPT_PAD_PKCS1);
        if(status>=0)return true;
    if(status==NTSTATUS(0xC000A000L))return false;
        throw rsa::Error{5};
    }
};
}
