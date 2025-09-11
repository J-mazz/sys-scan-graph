#include "../src/core/JSONWriter.h"
#include "../src/core/Report.h"
#include "../src/core/Config.h"
#include <iostream>
#include <array>
#include <cstring>
#include <cstdint>
#include <string>

// Canonical output stability test (schema change aware). Updates required only when intentional structural changes occur.

using namespace sys_scan;

namespace {
struct Sha256Ctx { uint32_t h[8]; uint64_t len=0; unsigned char buf[64]; size_t buf_len=0; };
static uint32_t rotr(uint32_t x, uint32_t n){ return (x>>n) | (x<<(32-n)); }
static void sha256_init(Sha256Ctx& c){ c.h[0]=0x6a09e667; c.h[1]=0xbb67ae85; c.h[2]=0x3c6ef372; c.h[3]=0xa54ff53a; c.h[4]=0x510e527f; c.h[5]=0x9b05688c; c.h[6]=0x1f83d9ab; c.h[7]=0x5be0cd19; c.len=0; c.buf_len=0; }
static void sha256_block(Sha256Ctx& c, const unsigned char* p){
    static const uint32_t K[64]={
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t w[64];
    for(int i=0;i<16;i++){ w[i]=(p[i*4]<<24)|(p[i*4+1]<<16)|(p[i*4+2]<<8)|p[i*4+3]; }
    for(int i=16;i<64;i++){ uint32_t s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3); uint32_t s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10); w[i]=w[i-16]+s0+w[i-7]+s1; }
    uint32_t a=c.h[0],b=c.h[1],c2=c.h[2],d=c.h[3],e=c.h[4],f=c.h[5],g=c.h[6],h=c.h[7];
    for(int i=0;i<64;i++){
        uint32_t S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
        uint32_t ch=(e&f)^((~e)&g);
        uint32_t temp1=h+S1+ch+K[i]+w[i];
        uint32_t S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
        uint32_t maj=(a&b)^(a&c2)^(b&c2);
        uint32_t temp2=S0+maj;
        h=g; g=f; f=e; e=d+temp1; d=c2; c2=b; b=a; a=temp1+temp2;
    }
    c.h[0]+=a; c.h[1]+=b; c.h[2]+=c2; c.h[3]+=d; c.h[4]+=e; c.h[5]+=f; c.h[6]+=g; c.h[7]+=h;
}
static void sha256_update(Sha256Ctx& c, const unsigned char* data, size_t len){
    c.len += len; size_t i=0;
    if(c.buf_len){ while(i<len && c.buf_len<64){ c.buf[c.buf_len++] = data[i++]; if(c.buf_len==64){ sha256_block(c,c.buf); c.buf_len=0; } } }
    for(; i+64<=len; i+=64) sha256_block(c, data+i);
    while(i<len){ c.buf[c.buf_len++]=data[i++]; if(c.buf_len==64){ sha256_block(c,c.buf); c.buf_len=0; } }
}
static void sha256_final(Sha256Ctx& c, unsigned char out[32]){
    uint64_t bitlen = c.len*8; c.buf[c.buf_len++] = 0x80;
    if(c.buf_len>56){ while(c.buf_len<64) c.buf[c.buf_len++]=0; sha256_block(c,c.buf); c.buf_len=0; }
    while(c.buf_len<56) c.buf[c.buf_len++]=0;
    for(int i=7;i>=0;--i){ c.buf[c.buf_len++] = (unsigned char)(bitlen>>(i*8)); }
    sha256_block(c,c.buf);
    for(int i=0;i<8;i++){ out[i*4]=(c.h[i]>>24)&0xFF; out[i*4+1]=(c.h[i]>>16)&0xFF; out[i*4+2]=(c.h[i]>>8)&0xFF; out[i*4+3]=c.h[i]&0xFF; }
}
static std::string sha256(const std::string& data){ Sha256Ctx ctx; sha256_init(ctx); sha256_update(ctx,(const unsigned char*)data.data(), data.size()); unsigned char md[32]; sha256_final(ctx, md); static const char* hex="0123456789abcdef"; std::string out; out.reserve(64); for(int i=0;i<32;i++){ out.push_back(hex[md[i]>>4]); out.push_back(hex[md[i]&0xF]); } return out; }
} // namespace

int main(){
    Config cfg; cfg.canonical=true; cfg.pretty=false; cfg.compact=true;
    Report r; r.start_scanner("dummy");
    Finding f; f.id="x"; f.title="Title"; f.description="Desc"; f.severity=Severity::Low; f.metadata["k"]="v"; r.add_finding("dummy", std::move(f)); r.end_scanner("dummy");
    setenv("SYS_SCAN_META_HOSTNAME","host",1);
    setenv("SYS_SCAN_META_KERNEL","kver",1);
    setenv("SYS_SCAN_META_ARCH","x86_64",1);
    setenv("SYS_SCAN_META_OS_ID","distro",1);
    setenv("SYS_SCAN_META_OS_VERSION","1",1);
    setenv("SYS_SCAN_META_OS_PRETTY","Pretty",1);
    setenv("SYS_SCAN_META_USER","user",1);
    setenv("SYS_SCAN_META_CMDLINE","cmd",1);
    setenv("SYS_SCAN_CANON_TIME_ZERO","1",1);
    setenv("SYS_SCAN_PROV_COMPILER_ID","cc",1);
    setenv("SYS_SCAN_PROV_COMPILER_VERSION","0",1);
    setenv("SYS_SCAN_PROV_GIT_COMMIT","deadbeef",1);
    setenv("SYS_SCAN_PROV_CXX_STANDARD","20",1);
    setenv("SYS_SCAN_PROV_CXX_FLAGS"," ",1);
    setenv("SYS_SCAN_PROV_SLSA_LEVEL","0",1);
    setenv("SYS_SCAN_PROV_BUILD_TYPE","Rel",1);
    JSONWriter w; auto json = w.write(r, cfg);
    auto h = sha256(json);
    const std::string expected_hash = "9cdccc998f62de99f4facd8bfaaa0d21beef4e33e9e2e8a9280e08d263382f68"; // updated for recent schema/metadata changes
    if(h!=expected_hash){ std::cerr << "Canonical hash mismatch: got="<<h<<" expected="<<expected_hash<<"\n"; return 1; }
    std::cout << "Canonical golden test passed" << std::endl; return 0; }
