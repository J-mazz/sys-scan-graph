module;
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <limits>

#ifdef SYS_SCAN_HAVE_ZLIB
#include <zlib.h>
#endif
#ifdef SYS_SCAN_HAVE_LZMA
#include <lzma.h>
#endif
#ifdef SYS_SCAN_HAVE_OPENSSL
#include <openssl/evp.h>
#endif

export module sys_scan.scanners.module_utils;

export namespace sys_scan {

// --- Compression Utils ---
class CompressionUtils {
public:
    static bool is_compressed(const std::string& path) {
        return path.size() > 3 && (path.ends_with(".ko.xz") || path.ends_with(".ko.gz"));
    }

    // Return decompressed buffer when bounded, else empty
    static std::string decompress_bounded(const std::string& full) {
        if (full.ends_with(".xz")) return decompress_xz_bounded(full);
        if (full.ends_with(".gz")) return decompress_gz_bounded(full);
        return {};
    }

    static std::string decompress_xz_bounded(const std::string& full) {
#ifdef SYS_SCAN_HAVE_LZMA
        std::ifstream f(full, std::ios::binary); if(!f) return {};
        f.seekg(0, std::ios::end);
        std::streamoff sz = f.tellg();
        if (sz < 0 || sz > 4 * 1024 * 1024) return {};
        f.seekg(0, std::ios::beg);

        lzma_stream strm = LZMA_STREAM_INIT;
        if(lzma_stream_decoder(&strm, UINT64_MAX, 0) != LZMA_OK) return {};

        std::string out;
        const size_t CHUNK = 8192;
        uint8_t inbuf[CHUNK];
        uint8_t outbuf[CHUNK];
        lzma_action action = LZMA_RUN;

        while(true) {
            if(strm.avail_in == 0) {
                f.read((char*)inbuf, CHUNK);
                strm.next_in = inbuf;
                strm.avail_in = static_cast<size_t>(f.gcount());
                if(strm.avail_in == 0) action = LZMA_FINISH;
            }
            strm.next_out = outbuf;
            strm.avail_out = CHUNK;

            lzma_ret ret = lzma_code(&strm, action);
            out.append((char*)outbuf, CHUNK - strm.avail_out);

            if(out.size() > 2 * 1024 * 1024) break; // cap decompressed output
            if(ret == LZMA_STREAM_END) break;
            if(ret != LZMA_OK) break;
        }
        lzma_end(&strm);
        return out;
#else
        return "";
#endif
    }

    static std::string decompress_gz_bounded(const std::string& full) {
#ifdef SYS_SCAN_HAVE_ZLIB
        gzFile g = gzopen(full.c_str(), "rb");
        if(!g) return {};
        std::string out;
        char buf[8192];
        int n;
        while((n = gzread(g, buf, sizeof(buf))) > 0) {
            out.append(buf, n);
            if(out.size() > 2 * 1024 * 1024) break; // cap decompressed output
        }
        gzclose(g);
        return out;
#else
        return "";
#endif
    }
};

// --- ELF Heuristics ---
class ElfModuleHeuristics {
public:
    struct SectionInfo {
        std::string name;
        uint64_t flags = 0;
        uint64_t size = 0;
    };

    static std::vector<SectionInfo> parse_sections(const std::string& file_path) {
        std::vector<SectionInfo> sections;
        std::ifstream ef(file_path, std::ios::binary);
        if (!ef) return sections;

        unsigned char ehdr[64]{};
        ef.read((char*)ehdr, sizeof(ehdr));
        std::streamsize read = ef.gcount();
        if (read < 52 || ehdr[0] != 0x7f || ehdr[1] != 'E' || ehdr[2] != 'L' || ehdr[3] != 'F') return sections;

        bool is64 = (ehdr[4] == 2);
        bool le = (ehdr[5] == 1);

        auto rd16 = [le](const unsigned char* p) {
            return le ? (uint16_t)p[0] | ((uint16_t)p[1] << 8) : (uint16_t)p[1] | ((uint16_t)p[0] << 8);
        };
        auto rd32 = [le](const unsigned char* p) {
            return le ? (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24)
                      : (uint32_t)p[3] | ((uint32_t)p[2] << 8) | ((uint32_t)p[1] << 16) | ((uint32_t)p[0] << 24);
        };
        auto rd64 = [le](const unsigned char* p) {
            uint64_t v = 0;
            if (le) {
                for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
            } else {
                for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
            }
            return v;
        };

        uint64_t e_shoff = is64 ? rd64(ehdr + 40) : rd32(ehdr + 32);
        uint16_t e_shentsize = rd16(ehdr + (is64 ? 58 : 46));
        uint16_t e_shnum = rd16(ehdr + (is64 ? 60 : 48));
        uint16_t e_shstrndx = rd16(ehdr + (is64 ? 62 : 50));

        if (!e_shoff || !e_shentsize || e_shnum == 0 || e_shnum > 8192) return sections;
        if (e_shstrndx >= e_shnum) return sections;

        ef.seekg(0, std::ios::end);
        std::streamoff file_size = ef.tellg();
        if (file_size < 0) return sections;
        ef.seekg(e_shoff, std::ios::beg);

        std::vector<unsigned char> sh_table(static_cast<size_t>(e_shentsize) * e_shnum);
        ef.read((char*)sh_table.data(), sh_table.size());
        if (ef.gcount() < (std::streamsize)sh_table.size()) return sections;

        // Locate shstrtab
        auto shdr_ptr = [&](uint16_t idx) {
            return sh_table.data() + static_cast<size_t>(idx) * e_shentsize;
        };
        const unsigned char* shstr = shdr_ptr(e_shstrndx);
        uint64_t shstr_off = is64 ? rd64(shstr + (is64 ? 24 : 16)) : rd32(shstr + 16);
        uint64_t shstr_size = is64 ? rd64(shstr + (is64 ? 32 : 20)) : rd32(shstr + 20);
        if (shstr_off + shstr_size > (uint64_t)file_size) shstr_size = (uint64_t)std::max<int64_t>(0, file_size - (int64_t)shstr_off);

        std::vector<char> shstrtab((size_t)shstr_size + 1, 0);
        ef.seekg(shstr_off, std::ios::beg);
        ef.read(shstrtab.data(), shstr_size);

        // Extract sections
        for (uint16_t i = 0; i < e_shnum; ++i) {
            const unsigned char* sh = shdr_ptr(i);
            uint32_t name_off = rd32(sh + 0);
            uint64_t flags = is64 ? rd64(sh + 8) : rd32(sh + 8);
            uint64_t size = is64 ? rd64(sh + 32) : rd32(sh + 20);
            std::string name;
            if (name_off < shstrtab.size()) {
                name = std::string(shstrtab.data() + name_off);
            }
            sections.push_back(SectionInfo{std::move(name), flags, size});
        }
        return sections;
    }

    static bool has_wx_section(const std::vector<SectionInfo>& sections) {
        static const uint64_t SHF_WRITE = 0x1, SHF_EXECINSTR = 0x4;
        for (const auto& s : sections) {
            if ((s.flags & SHF_EXECINSTR) && (s.flags & SHF_WRITE)) return true;
        }
        return false;
    }

    static bool has_suspicious_section_name(const std::vector<SectionInfo>& sections) {
        for (const auto& s : sections) {
            if (s.name == ".evil" || s.name == ".rootkit") return true;
        }
        return false;
    }
};

// --- Signature Analyzer ---
class SignatureAnalyzer {
public:
    static bool is_unsigned_module(const std::string& file_path) {
        std::ifstream f(file_path, std::ios::binary);
        if (!f) return false;

        std::string buffer(4096, '\0');
        f.read(&buffer[0], 4096);
        std::streamsize n = f.gcount();
        if (std::string(buffer.data(), (size_t)n).find("Module signature appended") != std::string::npos) return false;

        f.seekg(0, std::ios::end);
        auto size = f.tellg();
        if (size < 0) return true;
        std::streamoff read_sz = std::min<std::streamoff>(size, 4096);
        f.seekg(size - read_sz, std::ios::beg);
        f.read(&buffer[0], read_sz);
        n = f.gcount();
        return std::string(buffer.data(), (size_t)n).find("Module signature appended") == std::string::npos;
    }
};

}
