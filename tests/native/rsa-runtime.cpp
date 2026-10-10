// Standalone acceptance adapter; no executable is invoked by the crypto API.
#include "doof_rsa.hpp"
#include <fstream>
#include <thread>
#include <atomic>
#include <iostream>
using Bytes=std::vector<uint8_t>;
using doof_crypto::NativeRsaKey;
auto load(const std::string& path){std::ifstream f(path,std::ios::binary);if(!f)throw std::runtime_error("fixture missing");return std::make_shared<Bytes>(std::istreambuf_iterator<char>(f),std::istreambuf_iterator<char>());}
template<class T> T success(const doof::Result<T,int32_t>& r){if(auto v=std::get_if<doof::Success<T>>(&r))return v->value;throw std::runtime_error("RSA operation failed");}
int main(int argc,char**argv) {
    if(argc!=2)return 2;
    std::string root=argv[1];
    auto secret=doof_crypto::SecretBytes::steal(load(root+"/rsa-2048-private.pem"));
    auto privateKey=success(NativeRsaKey::fromPrivatePem(secret));secret->wipe();
    auto publicKey=success(NativeRsaKey::fromPublicPem(load(root+"/rsa-2048-public.pem")));
    auto message=std::make_shared<Bytes>(Bytes{0,1,255,0});
    auto signature=success(privateKey->sign(message));
    std::atomic<bool> ok{true};std::vector<std::thread> threads;
    for(int i=0;i<8;++i)threads.emplace_back([&]{for(int j=0;j<40;++j){if(*success(privateKey->sign(message))!=*signature||!success(publicKey->verify(message,signature)))ok=false;}});
    for(auto& t:threads)t.join();
    for(int i=0;i<100;++i){auto imported=success(NativeRsaKey::fromPrivatePem(doof_crypto::SecretBytes::steal(load(root+"/rsa-2048-pkcs8.pem"))));success(imported->sign(message));}
    if(!ok)return 1;std::cout<<"RSA concurrent use and lifecycle passed\n";
}
