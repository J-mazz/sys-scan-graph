// ╔══════════════════════════════════╗
// ║             MazzLabs             ║
// ╟──────────────────────────────────╢
// ║           Joseph Mazzini         ║
// ╚══════════════════════════════════╝

// ==============================================================================

#pragma once
#include "../core/Scanner.h"
#include <cstdint>

namespace sys_scan {

// Constants for lean network scanning
static constexpr size_t MAX_SOCKETS_LEAN = 1024;
static constexpr size_t MAX_INODE_LEN_LEAN = 16;
static constexpr size_t MAX_PATH_LEN_LEAN = 512;

class NetworkScanner : public Scanner {
public:
    std::string name() const override { return "network"; }
    std::string description() const override { return "Enumerate listening TCP/UDP sockets"; }
    void scan(ScanContext& context) override;
};

}
