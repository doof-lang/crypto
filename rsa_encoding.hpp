#pragma once
#include <cstdint>
#include <vector>
#include <stdexcept>
namespace doof_crypto::rsa {
using Bytes = std::vector<uint8_t>;
// Volatile writes prevent elision. Provider/caller copies cannot be erased here.
inline void wipe(Bytes& b) { volatile uint8_t* p = b.data(); for (size_t i=0;i<b.size();++i) p[i]=0; }
struct SecretBuffer { Bytes bytes; ~SecretBuffer() { wipe(bytes); } };
struct Error { int32_t code; };
struct View { const uint8_t* p; size_t n; };
struct Reader {
    View data; size_t offset = 0;
    bool done() const { return offset == data.n; }
    View read(uint8_t tag) {
        if (offset >= data.n || data.p[offset++] != tag || offset >= data.n) throw Error{0};
        size_t size = data.p[offset++];
        if (size & 128) {
            const size_t count = size & 127; size=0;
            if (!count || count>sizeof(size_t) || count>data.n-offset || !data.p[offset]) throw Error{0};
            for (size_t i=0;i<count;++i) size=(size<<8)|data.p[offset++];
            if (size<128) throw Error{0};
        }
        if (size>data.n-offset) throw Error{0};
        View result{data.p+offset,size}; offset+=size; return result;
    }
    void end() const { if (!done()) throw Error{0}; }
};
struct Parsed { SecretBuffer der; std::vector<View> integers; size_t bits = 0; };
void parse(const Bytes&, bool, Parsed&);
}
