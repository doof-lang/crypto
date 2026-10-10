#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#if defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_MAJOR < 3
#error OpenSSL 3 is required
#endif
int main() {
    EVP_MD_CTX* ctx=EVP_MD_CTX_new();EVP_PKEY_CTX* pk=nullptr;
    EVP_DigestSignInit(ctx,&pk,EVP_sha256(),nullptr,nullptr);
    EVP_DigestVerifyInit(ctx,&pk,EVP_sha256(),nullptr,nullptr);
    EVP_PKEY_CTX_set_rsa_padding(pk,RSA_PKCS1_PADDING);
    size_t size=0;EVP_DigestSign(ctx,nullptr,&size,nullptr,0);EVP_DigestVerify(ctx,nullptr,0,nullptr,0);
    const unsigned char* p=nullptr;EVP_PKEY_free(d2i_PrivateKey(EVP_PKEY_RSA,nullptr,&p,0));
    EVP_PKEY_free(d2i_PublicKey(EVP_PKEY_RSA,nullptr,&p,0));EVP_MD_CTX_free(ctx);
}
