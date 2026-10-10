#include "doof_rsa.hpp"
#include "rsa_encoding.hpp"
#include <algorithm>
#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif
#if defined(__APPLE__) && TARGET_OS_OSX && !DOOF_CRYPTO_RSA_EVP && !defined(DOOF_CRYPTO_RSA_STUB)
#include "rsa_apple.hpp"
#elif defined(_WIN32) && !defined(DOOF_CRYPTO_RSA_STUB)
#include "rsa_cng.hpp"
#elif DOOF_CRYPTO_RSA_EVP && !defined(DOOF_CRYPTO_RSA_STUB)
#include "rsa_evp.hpp"
#else
namespace doof_crypto {
struct NativeRsaKey::Backend {
    static std::unique_ptr<Backend> create(const rsa::Parsed&,bool) { throw rsa::Error{4}; }
    std::vector<uint8_t> sign(const std::vector<uint8_t>&) { throw rsa::Error{4}; }
    bool verify(const std::vector<uint8_t>&,const std::vector<uint8_t>&) { throw rsa::Error{4}; }
};
}
#endif
namespace doof_crypto {
NativeRsaKey::~NativeRsaKey() = default;
doof::Result<std::shared_ptr<NativeRsaKey>,int32_t> NativeRsaKey::import(const std::vector<uint8_t>& pem,bool priv) {
    try {
        rsa::Parsed parsed;rsa::parse(pem,priv,parsed);
        auto key=std::shared_ptr<NativeRsaKey>(new NativeRsaKey());
        key->backend_=Backend::create(parsed,priv);key->signatureSize_=(parsed.bits+7)/8;
        if(priv) {
            const std::vector<uint8_t> check={'D','o','o','f',' ','R','S','A',' ','i','m','p','o','r','t'};
            auto signature=key->backend_->sign(check);
            if(signature.size()!=key->signatureSize_||!key->backend_->verify(check,signature))throw rsa::Error{0};
        }
        return doof::Success<std::shared_ptr<NativeRsaKey>>{key};
    } catch(const rsa::Error& e) {return doof::Failure<int32_t>{e.code};}
    catch(const std::bad_alloc&) {return doof::Failure<int32_t>{5};}
}
doof::Result<std::shared_ptr<NativeRsaKey>,int32_t> NativeRsaKey::fromPrivatePem(const std::shared_ptr<SecretBytes>& pem) {return import(pem->unsafe_bytes(),true);}
doof::Result<std::shared_ptr<NativeRsaKey>,int32_t> NativeRsaKey::fromPublicPem(const std::shared_ptr<std::vector<uint8_t>>& pem) {return import(*pem,false);}
doof::Result<std::shared_ptr<std::vector<uint8_t>>,int32_t> NativeRsaKey::sign(const std::shared_ptr<std::vector<uint8_t>>& data) {
    try {std::lock_guard<std::mutex> guard(mutex_);return doof::Success<std::shared_ptr<std::vector<uint8_t>>>{std::make_shared<std::vector<uint8_t>>(backend_->sign(*data))};}
    catch(const rsa::Error& e){return doof::Failure<int32_t>{e.code};}catch(const std::bad_alloc&){return doof::Failure<int32_t>{5};}
}
doof::Result<bool,int32_t> NativeRsaKey::verify(const std::shared_ptr<std::vector<uint8_t>>& data,const std::shared_ptr<std::vector<uint8_t>>& sig) {
    if(sig->size()!=signatureSize_)return doof::Success<bool>{false};
    try {std::lock_guard<std::mutex> guard(mutex_);return doof::Success<bool>{backend_->verify(*data,*sig)};}
    catch(const rsa::Error& e){return doof::Failure<int32_t>{e.code};}catch(const std::bad_alloc&){return doof::Failure<int32_t>{5};}
}
}
