//    .________      ._____.___ .______  .______ .______ .___ .______  .___
//    :____.   \     :         |:      \ \____  |\____  |: __|:      \ : __|
//     __|  :/ |     |   \  /  ||   .   |/  ____|/  ____|| : ||       || : |
//    |     :  |     |   |\/   ||   :   |\      |\      ||   ||   |   ||   |
//     \__. __/      |___| |   ||___|   | \__:__| \__:__||   ||___|   ||   |
//        :/               |___|    |___|    :       :   |___|    |___||___|
//        :                                  •       •                      
//                                                                          
//                                                                          

// ==============================================================================

#pragma once
#include "../core/Scanner.h"

namespace sys_scan {

// Forward declaration to avoid circular includes
struct ScanContext;

class KernelHardeningScanner : public Scanner {
public:
    std::string name() const override { return "kernel_hardening"; }
    std::string description() const override { return "Checks kernel and platform hardening state (lockdown, secure boot, IMA, TPM, sysctls)"; }
    void scan(ScanContext& context) override;
};

}
