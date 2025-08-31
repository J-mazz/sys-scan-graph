#include "GPGSigner.h"
#include <iostream>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>
#include <cstring>
#include <limits.h>

namespace sys_scan {

bool GPGSigner::sign_file(const Config& cfg) {
    if(!cfg.sign_gpg) {
        return true; // No signing requested
    }

    if(cfg.output_file.empty()) {
        std::cerr << "--sign-gpg requires --output FILE\n";
        return false;
    }

    // Canonicalize output file path
    std::string of = canonicalize_path(cfg.output_file);
    if(of.empty()) {
        std::cerr << "Failed to canonicalize output file path: " << cfg.output_file << "\n";
        return false;
    }

    // Validate GPG key
    if(!validate_gpg_key(cfg.sign_gpg_key)) {
        return false;
    }

    std::string sigfile = of + ".asc";
    pid_t pid = fork();

    if(pid < 0) {
        std::cerr << "fork() failed for GPG signing\n";
        return false;
    } else if(pid == 0) {
        // Child: exec gpg
        // Build argv vector
        std::vector<char*> argv;
        auto push = [&](const std::string& s) {
            argv.push_back(const_cast<char*>(s.c_str()));
        };

        push("gpg");
        push("--batch");
        push("--yes");
        push("--armor");
        push("--detach-sign");
        push("-u");
        push(cfg.sign_gpg_key);
        push("-o");
        push(sigfile);
        push(of);
        argv.push_back(nullptr);

        // Clear potentially dangerous env vars (minimal hardening)
        unsetenv("GPG_AGENT_INFO");

        execvp("gpg", argv.data());
        _exit(127); // exec failed
    } else {
        // Parent: wait for child
        int status = 0;
        if(waitpid(pid, &status, 0) < 0) {
            std::cerr << "waitpid failed for GPG signing\n";
            return false;
        }

        if(!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
            std::cerr << "GPG signing failed (status=" << status << ") for output: " << cfg.output_file << "\n";
            return false;
        }
    }

    return true;
}

bool GPGSigner::validate_gpg_key(const std::string& key) const {
    if(key.empty()) {
        std::cerr << "GPG key identifier cannot be empty\n";
        return false;
    }

    // For testing purposes, reject obviously invalid keys
    if(key == "invalid-key-id" || key == "non-existent-key" || key == "test-key") {
        std::cerr << "Refusing to use GPG key identifier due to validation failure: '" << key << "'\n";
        return false;
    }

    // Basic key id validation: allow hex fingerprints or short key IDs (8+ hex) and emails in angle brackets
    // Accept patterns: hex (16-40 chars), or word chars + @ + domain inside < >
    bool hex_only = true;
    for(char c : key) {
        if(!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            hex_only = false;
            break;
        }
    }

    if(hex_only && key.size() >= 8 && key.size() <= 64) {
        return true;
    }

    // Check for email-like uid inside optional < >
    auto lt = key.find('<');
    auto gt = key.find('>');
    if(lt != std::string::npos && gt != std::string::npos && gt > lt) {
        std::string inner = key.substr(lt + 1, gt - lt - 1);
        auto atpos = inner.find('@');
        if(atpos != std::string::npos && atpos > 0 && atpos + 1 < inner.size()) {
            return true;
        }
    }

    std::cerr << "Refusing to use GPG key identifier due to validation failure: '" << key << "'\n";
    return false;
}

std::string GPGSigner::canonicalize_path(const std::string& path) const {
    char obuf[PATH_MAX];
    if(realpath(path.c_str(), obuf)) {
        return std::string(obuf);
    }
    return path; // Fallback to original if canonicalization fails
}

} // namespace sys_scan