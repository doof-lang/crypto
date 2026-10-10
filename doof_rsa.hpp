#pragma once
#include "doof_crypto.hpp"
#include <mutex>
namespace doof_crypto {
// Integer error codes are internal to the bridge; rsa.do supplies typed errors.
class NativeRsaKey {
public:
    ~NativeRsaKey();
    static doof::Result<std::shared_ptr<NativeRsaKey>, int32_t> fromPrivatePem(const std::shared_ptr<SecretBytes>&);
    static doof::Result<std::shared_ptr<NativeRsaKey>, int32_t> fromPublicPem(const std::shared_ptr<std::vector<uint8_t>>&);
    doof::Result<std::shared_ptr<std::vector<uint8_t>>, int32_t> sign(const std::shared_ptr<std::vector<uint8_t>>&);
    doof::Result<bool, int32_t> verify(const std::shared_ptr<std::vector<uint8_t>>&, const std::shared_ptr<std::vector<uint8_t>>&);
private:
    NativeRsaKey() = default;
    static doof::Result<std::shared_ptr<NativeRsaKey>, int32_t> import(const std::vector<uint8_t>&, bool);
    struct Backend;
    std::unique_ptr<Backend> backend_;
    std::mutex mutex_;
    size_t signatureSize_ = 0;
};
}
