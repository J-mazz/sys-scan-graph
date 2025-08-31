#include "OutputWriter.h"
#include "BuildInfo.h"
#include <iostream>
#include <unistd.h>
#include <limits.h>
#include <filesystem>
#ifdef SYS_SCAN_HAVE_OPENSSL
#include <openssl/evp.h>
#endif

namespace sys_scan {

bool OutputWriter::write_report(const Report& report, const Config& cfg) {
    // Config is passed directly to JSONWriter, no need for global state
    std::string json = json_writer_.write(report, cfg);
    json = format_json(json, cfg);

    if(cfg.output_file.empty()) {
        std::cout << json;
    } else {
        std::ofstream ofs(cfg.output_file);
        if(!ofs) {
            std::cerr << "Failed to open output file: " << cfg.output_file << "\n";
            return false;
        }
        ofs << json;
    }

    return true;
}

bool OutputWriter::write_env_file(const Config& cfg) {
    if(cfg.write_env_file.empty()) {
        return true; // No env file requested
    }

    // Check if output file exists (required for env file generation)
    if(!cfg.output_file.empty() && !std::filesystem::exists(cfg.output_file)) {
        return false;
    }

    std::ofstream envf(cfg.write_env_file);
    if(!envf) {
        std::cerr << "Failed to open env file: " << cfg.write_env_file << "\n";
        return false;
    }

    envf << "SYS_SCAN_VERSION=" << sys_scan::buildinfo::APP_VERSION << "\n";

    // Add output file path if specified
    if(!cfg.output_file.empty()) {
        envf << "SYS_SCAN_OUTPUT_FILE=" << cfg.output_file << "\n";
    }

    // Calculate output file SHA256 if possible
    std::string output_hexhash;
    if(!cfg.output_file.empty()) {
#ifdef SYS_SCAN_HAVE_OPENSSL
        FILE* fp = fopen(cfg.output_file.c_str(), "rb");
        if(fp) {
            unsigned char md[32];
            unsigned int mdlen = 0;
            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if(ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1) {
                unsigned char bufh[8192];
                size_t got;
                while((got = fread(bufh, 1, sizeof(bufh), fp)) > 0) {
                    EVP_DigestUpdate(ctx, bufh, got);
                }
                if(EVP_DigestFinal_ex(ctx, md, &mdlen) == 1 && mdlen == 32) {
                    static const char* hx = "0123456789abcdef";
                    for(unsigned i = 0; i < 32; i++) {
                        output_hexhash.push_back(hx[md[i] >> 4]);
                        output_hexhash.push_back(hx[md[i] & 0xF]);
                    }
                }
            }
            if(ctx) EVP_MD_CTX_free(ctx);
            fclose(fp);
        }
#endif
        envf << "SYS_SCAN_SHA256=" << output_hexhash << "\n";
    }

    // Calculate binary SHA256 if possible
    std::string binary_hexhash;
#ifdef SYS_SCAN_HAVE_OPENSSL
    char pathbuf[4096];
    ssize_t n = readlink("/proc/self/exe", pathbuf, sizeof(pathbuf) - 1);
    if(n > 0) {
        pathbuf[n] = 0;
        std::string exe = pathbuf;

        if(!exe.empty()) {
            FILE* fp = fopen(exe.c_str(), "rb");
            if(fp) {
                unsigned char md[32];
                unsigned int mdlen = 0;
                EVP_MD_CTX* ctx = EVP_MD_CTX_new();
                if(ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1) {
                    unsigned char bufh[8192];
                    size_t got;
                    while((got = fread(bufh, 1, sizeof(bufh), fp)) > 0) {
                        EVP_DigestUpdate(ctx, bufh, got);
                    }
                    if(EVP_DigestFinal_ex(ctx, md, &mdlen) == 1 && mdlen == 32) {
                        static const char* hx = "0123456789abcdef";
                        for(unsigned i = 0; i < 32; i++) {
                            binary_hexhash.push_back(hx[md[i] >> 4]);
                            binary_hexhash.push_back(hx[md[i] & 0xF]);
                        }
                    }
                }
                if(ctx) EVP_MD_CTX_free(ctx);
                fclose(fp);
            }
        }
    }
#endif

    envf << "SYS_SCAN_BINARY_SHA256=" << binary_hexhash << "\n";
    return true;
}

std::string OutputWriter::format_json(const std::string& json, const Config& cfg) const {
    if(cfg.pretty) {
        // Simple pretty formatting: add newlines and indentation
        std::string result;
        int indent = 0;
        bool in_string = false;

        for(size_t i = 0; i < json.length(); ++i) {
            char c = json[i];

            if(c == '"' && (i == 0 || json[i-1] != '\\')) {
                in_string = !in_string;
                result += c;
            } else if(!in_string) {
                if(c == '{' || c == '[') {
                    result += c;
                    result += '\n';
                    indent += 2;
                    result += std::string(indent, ' ');
                } else if(c == '}' || c == ']') {
                    result += '\n';
                    indent -= 2;
                    result += std::string(indent, ' ');
                    result += c;
                } else if(c == ',') {
                    result += c;
                    result += '\n';
                    result += std::string(indent, ' ');
                } else if(c == ':') {
                    result += c;
                    result += ' ';
                } else {
                    result += c;
                }
            } else {
                result += c;
            }
        }
        return result;
    }
    return json;
}

} // namespace sys_scan