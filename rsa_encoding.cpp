#include "rsa_encoding.hpp"
#include <algorithm>
#include <string_view>
namespace doof_crypto::rsa {
namespace {
bool space(uint8_t c) { return c==' ' || c=='\t' || c=='\r' || c=='\n' || c=='\f' || c=='\v'; }
int base64(uint8_t c) {
    if(c>='A'&&c<='Z')return c-'A';
    if(c>='a'&&c<='z')return c-'a'+26;
    if(c>='0'&&c<='9')return c-'0'+52;
    if(c=='+')return 62;
    if(c=='/')return 63;
    return -1;
}
View integer(Reader& r) {
    auto v=r.read(2);
    if (!v.n || (v.p[0]&128) || (v.n>1 && v.p[0]==0 && !(v.p[1]&128))) throw Error{0};
    if(v.n>1 && v.p[0]==0) {++v.p;--v.n;} return v;
}
bool zero(View v) { return v.n==1 && v.p[0]==0; }
void algorithm(Reader& r) {
    Reader a{r.read(0x30)}; auto oid=a.read(6);
    const uint8_t rsaOid[]={0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1};
    if(oid.n!=sizeof(rsaOid)||!std::equal(oid.p,oid.p+oid.n,rsaOid))throw Error{1};
    if(a.read(5).n!=0)throw Error{0};
    a.end();
}
}
void parse(const Bytes& pem, bool privateKey, Parsed& out) {
    if(pem.size()>32768)throw Error{3};
    if(pem.empty())throw Error{0};
    out.der.bytes.reserve(pem.size()*3/4);
    size_t start=0,end=pem.size();
    while(start<end&&space(pem[start]))++start;
    while(end>start&&space(pem[end-1]))--end;
    std::string_view text(reinterpret_cast<const char*>(pem.data()+start),end-start);
    if(text.substr(0,11)!="-----BEGIN ")throw Error{0};
    auto labelEnd=text.find("-----",11);
    if(labelEnd==text.npos)throw Error{0};
    auto label=text.substr(11,labelEnd-11);
    if(label=="ENCRYPTED PRIVATE KEY")throw Error{2};
    bool wrapped=label=="PRIVATE KEY"||label=="PUBLIC KEY";
    if(privateKey ? label!="PRIVATE KEY"&&label!="RSA PRIVATE KEY" : label!="PUBLIC KEY"&&label!="RSA PUBLIC KEY")throw Error{1};
    std::string footer="-----END ";footer.append(label);footer+="-----";
    if(text.size()<footer.size()||text.substr(text.size()-footer.size())!=footer)throw Error{0};
    auto body=text.substr(labelEnd+5,text.size()-footer.size()-labelEnd-5);
    if(body.find("Proc-Type:")!=body.npos||body.find("DEK-Info:")!=body.npos)throw Error{2};
    int quartet[4];size_t count=0;bool finished=false;
    for(uint8_t c:body) {
        if(space(c))continue;
    if(finished)throw Error{0};
        int v=c=='='?64:base64(c);
    if(v<0)throw Error{0};
        quartet[count++]=v;
        if(count==4) {
            int a=quartet[0],b=quartet[1],c2=quartet[2],d=quartet[3];
            if(a==64||b==64||(c2==64&&d!=64))throw Error{0};
            out.der.bytes.push_back(uint8_t((a<<2)|(b>>4)));
            if(c2==64) {if(b&15)throw Error{0};finished=true;}
            else {out.der.bytes.push_back(uint8_t((b<<4)|(c2>>2)));
                if(d==64){if(c2&3)throw Error{0};finished=true;}
                else out.der.bytes.push_back(uint8_t((c2<<6)|d));}
            count=0;
        }
    }
    if(count||out.der.bytes.empty())throw Error{0};
    View key{out.der.bytes.data(),out.der.bytes.size()};
    if(wrapped) {
        Reader outer{key};Reader seq{outer.read(0x30)};outer.end();
        if(privateKey&&!zero(integer(seq)))throw Error{0};
        algorithm(seq);
        key=seq.read(privateKey?4:3);seq.end();
        if(!privateKey) {if(!key.n||key.p[0]!=0)throw Error{0};++key.p;--key.n;}
    }
    // Preserve the validated PKCS#1 representation for all backend imports.
    SecretBuffer normalized;normalized.bytes.assign(key.p,key.p+key.n);
    wipe(out.der.bytes);out.der.bytes=std::move(normalized.bytes);
    Reader outer{{out.der.bytes.data(),out.der.bytes.size()}};
    Reader seq{outer.read(0x30)};outer.end();
    if(privateKey) {auto version=integer(seq);
    if(!zero(version))throw Error{3};}
    size_t fields=privateKey?8:2;
    for(size_t i=0;i<fields;++i) {auto v=integer(seq);
    if(zero(v))throw Error{0};
        out.integers.push_back(v);}
    seq.end();
    auto n=out.integers[0],e=out.integers[1];
    size_t leading=0;for(uint8_t mask=128;mask&&!(n.p[0]&mask);mask>>=1)++leading;
    out.bits=n.n*8-leading;
    if(out.bits<2048||out.bits>8192||!(n.p[n.n-1]&1)||e.n>8||!(e.p[e.n-1]&1)||(e.n==1&&e.p[0]<3))throw Error{3};
}
}
