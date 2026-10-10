#pragma once
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
namespace doof_crypto {
struct NativeRsaKey::Backend {
    std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key{nullptr,EVP_PKEY_free};
    static std::unique_ptr<Backend> create(const rsa::Parsed& parsed,bool priv) {
        auto result=std::make_unique<Backend>();
        const unsigned char* p=parsed.der.bytes.data();
        ERR_clear_error();
        result->key.reset(priv?d2i_PrivateKey(EVP_PKEY_RSA,nullptr,&p,parsed.der.bytes.size()):d2i_PublicKey(EVP_PKEY_RSA,nullptr,&p,parsed.der.bytes.size()));
        if(!result->key||p!=parsed.der.bytes.data()+parsed.der.bytes.size())throw rsa::Error{0};
        return result;
    }
    rsa::Bytes sign(const rsa::Bytes& message) {
        std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),EVP_MD_CTX_free);
        EVP_PKEY_CTX* pk=nullptr;ERR_clear_error();
        if(!ctx||EVP_DigestSignInit(ctx.get(),&pk,EVP_sha256(),nullptr,key.get())!=1||EVP_PKEY_CTX_set_rsa_padding(pk,RSA_PKCS1_PADDING)!=1)throw rsa::Error{5};
        size_t size=0;
        if(EVP_DigestSign(ctx.get(),nullptr,&size,message.data(),message.size())!=1)throw rsa::Error{5};
        rsa::Bytes signature(size);
        if(EVP_DigestSign(ctx.get(),signature.data(),&size,message.data(),message.size())!=1)throw rsa::Error{5};
        signature.resize(size);return signature;
    }
    bool verify(const rsa::Bytes& message,const rsa::Bytes& signature) {
        std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),EVP_MD_CTX_free);
        EVP_PKEY_CTX* pk=nullptr;ERR_clear_error();
        if(!ctx||EVP_DigestVerifyInit(ctx.get(),&pk,EVP_sha256(),nullptr,key.get())!=1||EVP_PKEY_CTX_set_rsa_padding(pk,RSA_PKCS1_PADDING)!=1)throw rsa::Error{5};
        int status=EVP_DigestVerify(ctx.get(),signature.data(),signature.size(),message.data(),message.size());
        if(status==1)return true;
    if(status==0){ERR_clear_error();return false;}throw rsa::Error{5};
    }
};
}
