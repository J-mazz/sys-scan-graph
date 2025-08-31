#include "ModuleHelpers.h"
#include "ModuleUtils.h"
#include <fstream>
#include <sstream>
#include <cstring>
#include <vector>
#include <cstdint>
#ifdef SYS_SCAN_HAVE_OPENSSL
#include <openssl/evp.h>
#endif

namespace sys_scan {

std::string CompressionUtils::decompress_xz_bounded(const std::string& path) {
    return sys_scan::decompress_xz_bounded(path);
}

std::string CompressionUtils::decompress_gz_bounded(const std::string& path) {
    return sys_scan::decompress_gz_bounded(path);
}

bool CompressionUtils::is_compressed(const std::string& path) {
    return path.rfind(".ko.xz") == path.size() - 6 || path.rfind(".ko.gz") == path.size() - 6;
}

std::vector<ElfModuleHeuristics::SectionInfo> ElfModuleHeuristics::parse_sections(const std::string& file_path) {
    std::vector<SectionInfo> sections;
    std::ifstream ef(file_path, std::ios::binary);
    if (!ef) return sections;

    unsigned char ehdr[64];
    ef.read((char*)ehdr, sizeof(ehdr));
    if (ef.gcount() < 52 || ehdr[0] != 0x7f || ehdr[1] != 'E' || ehdr[2] != 'L' || ehdr[3] != 'F') return sections;

    bool is64 = (ehdr[4] == 2);
    bool le = (ehdr[5] == 1);
    auto rd16 = [&](const unsigned char* p) { return le ? (uint16_t)p[0] | ((uint16_t)p[1] << 8) : (uint16_t)p[1] | ((uint16_t)p[0] << 8); };
    auto rd32 = [&](const unsigned char* p) { return le ? (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24) : (uint32_t)p[3] | ((uint32_t)p[2] << 8) | ((uint32_t)p[1] << 16) | ((uint32_t)p[0] << 24); };
    auto rd64 = [&](const unsigned char* p) {
        uint64_t v = 0;
        if (le) { for (int i = 7; i >= 0; --i) { v = (v << 8) | p[i]; } }
        else { for (int i = 0; i < 8; i++) { v = (v << 8) | p[i]; } }
        return v;
    };

    uint16_t e_shentsize = rd16(ehdr + (is64 ? 58 : 46));
    uint16_t e_shnum = rd16(ehdr + (is64 ? 60 : 48));
    uint32_t e_shoff32 = rd32(ehdr + (is64 ? 40 : 32));
    uint64_t e_shoff = is64 ? rd64(ehdr + 40) : e_shoff32;

    if (!e_shoff || !e_shentsize || e_shnum > 512) return sections;

    ef.seekg(e_shoff, std::ios::beg);
    std::vector<unsigned char> shbuf(e_shentsize);
    for (uint16_t si = 0; si < e_shnum; ++si) {
        if (!ef.read((char*)shbuf.data(), e_shentsize)) break;
        uint64_t flags = 0, size = 0;
        if (is64) {
            flags = rd64(&shbuf[8]);
            size = rd64(&shbuf[32]);
        } else {
            flags = rd32(&shbuf[8]);
            size = rd32(&shbuf[16]);
        }
        sections.push_back(SectionInfo{"", flags, size});
    }

    uint16_t e_shstrndx = rd16(ehdr + (is64 ? 62 : 50));
    if (e_shstrndx < sections.size()) {
        ef.seekg(e_shoff + (uint64_t)e_shstrndx * e_shentsize, std::ios::beg);
        std::vector<unsigned char> sh(e_shentsize);
        if (ef.read((char*)sh.data(), e_shentsize)) {
            uint64_t stroff = is64 ? rd64(&sh[24]) : rd32(&sh[16]);
            uint64_t strsize = is64 ? rd64(&sh[32]) : rd32(&sh[20]);
            if (stroff && strsize < 1 * 1024 * 1024) {
                std::vector<char> strtab(strsize);
                ef.seekg(stroff, std::ios::beg);
                if (ef.read(strtab.data(), strsize)) {
                    ef.seekg(e_shoff, std::ios::beg);
                    for (uint16_t si = 0; si < sections.size(); ++si) {
                        if (!ef.read((char*)shbuf.data(), e_shentsize)) break;
                        uint32_t name_off = rd32(&shbuf[0]);
                        if (name_off < strtab.size()) sections[si].name = std::string(&strtab[name_off]);
                    }
                }
            }
        }
    }

    return sections;
}

bool ElfModuleHeuristics::has_wx_section(const std::vector<SectionInfo>& sections) {
    static const uint64_t SHF_WRITE = 0x1, SHF_EXECINSTR = 0x4;
    for (const auto& s : sections) {
        if ((s.flags & SHF_EXECINSTR) && (s.flags & SHF_WRITE)) return true;
    }
    return false;
}

bool ElfModuleHeuristics::has_large_text_section(const std::vector<SectionInfo>& sections) {
    for (const auto& s : sections) {
        if (s.name == ".text" && s.size > 5 * 1024 * 1024) return true;
    }
    return false;
}

bool ElfModuleHeuristics::has_suspicious_section_name(const std::vector<SectionInfo>& sections) {
    auto suspicious = [](const std::string& n) {
        if (n.empty()) return false;
        static const char* bad[] = {".evil", ".rootkit", ".hide", ".__mod", ".__kern", ".backdoor"};
        for (auto* b : bad) { if (n == b) return true; }
        if (n.size() == 1) return true;
        if (n[0] == '.' && n.size() > 1 && std::isdigit((unsigned char)n[1]) && std::isdigit((unsigned char)n.back())) return true;
        return false;
    };
    for (const auto& s : sections) {
        if (suspicious(s.name)) return true;
    }
    return false;
}

bool SignatureAnalyzer::is_unsigned_module(const std::string& file_path) {
    auto read_file_prefix = [](const std::string& p, size_t max_bytes) {
        std::ifstream f(p, std::ios::binary);
        if (!f) return std::string();
        std::string data;
        data.resize(max_bytes);
        f.read(&data[0], max_bytes);
        data.resize(f.gcount());
        return data;
    };
    auto read_file_all = [](const std::string& p) {
        std::ifstream f(p, std::ios::binary);
        if (!f) return std::string();
        std::ostringstream oss;
        oss << f.rdbuf();
        return oss.str();
    };

    std::string contents = read_file_prefix(file_path, 4096);
    if (contents.find("Module signature appended") != std::string::npos) return false;
    contents = read_file_all(file_path);
    return contents.find("Module signature appended") == std::string::npos;
}

std::string SignatureAnalyzer::compute_sha256(const std::string& file_path) {
#ifdef SYS_SCAN_HAVE_OPENSSL
    std::ifstream mf(file_path, std::ios::binary);
    if (!mf) return "";
    unsigned char md[32];
    unsigned int mdlen = 0;
    std::vector<unsigned char> buf(8192);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    size_t totalb = 0;
    while (mf && totalb < 2 * 1024 * 1024) {
        mf.read((char*)buf.data(), buf.size());
        auto got = mf.gcount();
        if (got <= 0) break;
        EVP_DigestUpdate(ctx, buf.data(), (size_t)got);
        totalb += (size_t)got;
    }
    if (EVP_DigestFinal_ex(ctx, md, &mdlen) != 1 || mdlen != 32) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    EVP_MD_CTX_free(ctx);
    static const char* hex = "0123456789abcdef";
    std::string hexhash;
    hexhash.reserve(64);
    for (unsigned i = 0; i < 32; i++) {
        hexhash.push_back(hex[md[i] >> 4]);
        hexhash.push_back(hex[md[i] & 0xF]);
    }
    return hexhash;
#else
    return "";
#endif
}

} // namespace sys_scan