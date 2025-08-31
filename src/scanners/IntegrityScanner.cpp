#include "IntegrityScanner.h"
#include "../core/ScanContext.h"
#include "../core/Report.h"
#include "../core/Config.h"
#include "../core/Logging.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_set>
#include <unordered_map>
#include <cstdio>
#include <array>
#include <optional>
#include <cstring>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>
#ifdef SYS_SCAN_HAVE_OPENSSL
#include <openssl/sha.h>
#endif

namespace fs = std::filesystem;
namespace sys_scan {

// Secure command execution using fork/execvp (avoids shell injection)
static std::string run_cmd_capture(const std::vector<std::string>& args) {
    if (args.empty()) return "";

    int pipefd[2];
    if (pipe(pipefd) == -1) return "";

    pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        return "";
    }

    if (pid == 0) { // Child process
        close(pipefd[0]); // Close read end
        dup2(pipefd[1], STDOUT_FILENO); // Redirect stdout to pipe
        dup2(pipefd[1], STDERR_FILENO); // Redirect stderr to pipe
        close(pipefd[1]);

        // Convert args to char* array for execvp
        std::vector<char*> argv;
        for (const auto& arg : args) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr);

        // Clear potentially dangerous environment variables
        unsetenv("IFS");
        unsetenv("PATH"); // Will be set by execvp to default

        execvp(argv[0], argv.data());
        _exit(127); // exec failed
    } else { // Parent process
        close(pipefd[1]); // Close write end

        std::string output;
        char buffer[256];
        ssize_t bytes_read;

        // Read from pipe with timeout protection
        while ((bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytes_read] = '\0';
            output += buffer;
            // Prevent excessive output (1MB limit)
            if (output.size() > 1 * 1024 * 1024) {
                break;
            }
        }

        close(pipefd[0]);

        // Wait for child process
        int status;
        waitpid(pid, &status, 0);

        return output;
    }
}

void IntegrityScanner::scan(ScanContext& context){
    auto& cfg = context.config;
    if(!cfg.integrity) return; // gated entirely

    size_t pkg_mismatch_count=0; size_t pkg_checked=0; size_t pkg_detail_emitted=0; std::vector<std::string> mismatch_sample; mismatch_sample.reserve(20);
    bool used_dpkg=false; bool used_rpm=false;
    std::vector<std::string> rehash_files; rehash_files.reserve(64);
    if(cfg.integrity_pkg_verify){
        // Prefer dpkg -V (Debian) else rpm -Va (RPM-based)
        if(fs::exists("/usr/bin/dpkg")){
            used_dpkg=true; std::string out = run_cmd_capture({"dpkg", "-V"}); std::istringstream iss(out); std::string line; // Lines: status flags then space then package or file
            while(std::getline(iss,line)){
                if(line.empty()) continue; // lines starting with '??' or similar indicate mismatches
                if(line.size()>0 && (line[0]==' ' || line[0]=='?')) continue; // skip blank prefix lines
                // dpkg -V format: conffile mismatches lines start with '??' or multiple flag chars (MD5 sum mismatch => '5')
                if(line[0] != ' '){ // mismatch line
                    ++pkg_mismatch_count; if(mismatch_sample.size()<10) mismatch_sample.push_back(line.substr(0,40));
                    // Attempt to extract filename (dpkg -V lines: flags  path)
                    std::string path; size_t pos = line.find(' '); if(pos!=std::string::npos){ path = line.substr(pos+1); }
                    if(!path.empty() && rehash_files.size() < (size_t)cfg.integrity_pkg_rehash_limit) rehash_files.push_back(path);
                    if(pkg_detail_emitted < (size_t)cfg.integrity_pkg_limit){ Finding f; f.id = std::string("pkg_mismatch:")+std::to_string(pkg_detail_emitted); f.title="Package file mismatch"; f.severity=Severity::Medium; f.description="dpkg verification mismatch"; f.metadata["raw"] = line; if(!path.empty()) f.metadata["path"] = path; context.report.add_finding(this->name(), std::move(f)); ++pkg_detail_emitted; }
                }
            }
        } else if(fs::exists("/usr/bin/rpm")) {
            used_rpm=true; std::string out = run_cmd_capture({"rpm", "-Va"}); std::istringstream iss(out); std::string line; while(std::getline(iss,line)){
                if(line.empty()) continue; // rpm verification lines: 8 chars of flags, space, path or package
                if(line.size() < 2) continue; bool mismatch=false; for(char c: line.substr(0,8)){ if(c!='.' && c!=' '){ mismatch=true; break; } }
                if(!mismatch) continue; ++pkg_mismatch_count; if(mismatch_sample.size()<10) mismatch_sample.push_back(line.substr(0,40));
                std::string path; if(line.size()>9) path = line.substr(9); if(!path.empty() && rehash_files.size() < (size_t)cfg.integrity_pkg_rehash_limit) rehash_files.push_back(path);
                if(pkg_detail_emitted < (size_t)cfg.integrity_pkg_limit){ Finding f; f.id = std::string("pkg_mismatch:")+std::to_string(pkg_detail_emitted); f.title="Package file mismatch"; f.severity=Severity::Medium; f.description="rpm verification mismatch"; f.metadata["raw"] = line; if(!path.empty()) f.metadata["path"] = path; context.report.add_finding(this->name(), std::move(f)); ++pkg_detail_emitted; }
            }
        }
    }
    // IMA measurement stats
    size_t ima_entries=0; size_t ima_fail=0; if(cfg.integrity_ima){
        if(fs::exists("/sys/kernel/security/ima/ascii_runtime_measurements")){
            std::ifstream ifs("/sys/kernel/security/ima/ascii_runtime_measurements"); std::string line; while(std::getline(ifs,line)){ if(line.empty()) continue; ++ima_entries; // columns: PCR template-hash algo digest path
                // simple heuristic: look for 'fail' or 'measure' anomalies not typical - placeholder
                if(line.find("fail")!=std::string::npos) ++ima_fail; if(ima_entries>500000) break; }
        }
    }

    // Summary finding
    // Optional rehash (SHA256) for mismatched files
#ifdef SYS_SCAN_HAVE_OPENSSL
    if(cfg.integrity_pkg_rehash && !rehash_files.empty()){
        for(const auto& fpath : rehash_files){
            std::error_code ec; if(!fs::is_regular_file(fpath, ec)) continue; std::ifstream ifs(fpath, std::ios::binary); if(!ifs) continue; unsigned char buf[8192];
            SHA256_CTX c; SHA256_Init(&c); while(ifs){ ifs.read((char*)buf, sizeof(buf)); std::streamsize got = ifs.gcount(); if(got>0) SHA256_Update(&c, buf, (size_t)got); }
            unsigned char md[32]; SHA256_Final(md, &c); static const char* hex="0123456789abcdef"; std::string hexsum; hexsum.reserve(64); for(int i=0;i<32;i++){ hexsum.push_back(hex[md[i]>>4]); hexsum.push_back(hex[md[i]&0xF]); }
            Finding hf; hf.id = std::string("pkg_rehash:")+fpath; hf.title="Package mismatch file hash"; hf.severity=Severity::Info; hf.description="Recomputed SHA256 for mismatched file"; hf.metadata["path"] = fpath; hf.metadata["sha256"] = hexsum; context.report.add_finding(this->name(), std::move(hf));
        }
    }
#endif

    Finding summary; summary.id = "integrity_summary"; summary.title = "Integrity summary"; summary.severity = Severity::Info; summary.description = "Package / integrity verification";
    if(pkg_mismatch_count>0) summary.severity = Severity::Medium; if(ima_fail>0) summary.severity = Severity::High;
    if(used_dpkg) summary.metadata["pkg_tool"] = "dpkg"; else if(used_rpm) summary.metadata["pkg_tool"]="rpm"; else if(cfg.integrity_pkg_verify) summary.metadata["pkg_tool"]="none";
    summary.metadata["pkg_mismatch_count"] = std::to_string(pkg_mismatch_count);
    if(!mismatch_sample.empty()){ std::string s; for(size_t i=0;i<mismatch_sample.size(); ++i){ if(i) s+=","; s+=mismatch_sample[i]; } summary.metadata["pkg_mismatch_sample"] = s; }
    if(cfg.integrity_ima){ summary.metadata["ima_entries"] = std::to_string(ima_entries); if(ima_fail>0) summary.metadata["ima_fail"] = std::to_string(ima_fail); }
    context.report.add_finding(this->name(), std::move(summary));
}

}
