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

class AuditdScanner : public Scanner {
public:
    std::string name() const override { return "auditd"; }
    std::string description() const override { return "Checks auditd rules coverage for execve and privilege-escalation events"; }
    void scan(ScanContext& context) override;
};

}
