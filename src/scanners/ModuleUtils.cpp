#include "ModuleUtils.h"
#include <fstream>
#include <string>
#include <cstdint>
#ifdef SYS_SCAN_HAVE_LZMA
#include <lzma.h>
#endif
#ifdef SYS_SCAN_HAVE_ZLIB
#include <zlib.h>
#endif

namespace sys_scan {
namespace {
constexpr size_t MAX_COMPRESSED_SIZE = 4 * 1024 * 1024;      // 4MB
constexpr size_t MAX_DECOMPRESSED_SIZE = 2 * 1024 * 1024;    // 2MB
}

std::string decompress_xz_bounded(const std::string& full){
#ifdef SYS_SCAN_HAVE_LZMA
    std::ifstream f(full, std::ios::binary); if(!f) return {};
    f.seekg(0, std::ios::end); std::streamoff sz = f.tellg(); if(sz > 0 && (size_t)sz > MAX_COMPRESSED_SIZE) { return {}; }
    f.seekg(0, std::ios::beg);
    lzma_stream strm = LZMA_STREAM_INIT; if(lzma_stream_decoder(&strm, UINT64_MAX, 0)!=LZMA_OK) return {};
    std::string out; out.reserve(65536);
    uint8_t inbuf[8192]; uint8_t outbuf[8192];
    lzma_action action = LZMA_RUN;
    while(true){
        if(strm.avail_in == 0){ f.read(reinterpret_cast<char*>(inbuf), sizeof(inbuf)); std::streamsize got = f.gcount(); if(got <= 0){ action = LZMA_FINISH; } else { strm.next_in = inbuf; strm.avail_in = (size_t)got; } }
        strm.next_out = outbuf; strm.avail_out = sizeof(outbuf);
        auto rc = lzma_code(&strm, action);
        size_t produced = sizeof(outbuf) - strm.avail_out; if(produced) out.append(reinterpret_cast<char*>(outbuf), produced);
        if(out.size() > MAX_DECOMPRESSED_SIZE){ break; }
        if(rc == LZMA_STREAM_END) break; if(rc != LZMA_OK && rc != LZMA_STREAM_END){ out.clear(); break; }
        if(action == LZMA_FINISH && rc != LZMA_OK && rc != LZMA_STREAM_END){ out.clear(); break; }
    }
    lzma_end(&strm); return out;
#else
    (void)full; return std::string();
#endif
}

std::string decompress_gz_bounded(const std::string& full){
#ifdef SYS_SCAN_HAVE_ZLIB
    gzFile g = gzopen(full.c_str(), "rb"); if(!g) return {}; std::string out; out.reserve(65536); char buf[8192]; int n; size_t total_in=0; while((n=gzread(g, buf, sizeof(buf)))>0){ out.append(buf, n); total_in += (size_t)n; if(out.size()>MAX_DECOMPRESSED_SIZE) break; if(total_in > MAX_COMPRESSED_SIZE) { out.clear(); break; } } gzclose(g); return out;
#else
    (void)full; return std::string();
#endif
}

} // namespace sys_scan
