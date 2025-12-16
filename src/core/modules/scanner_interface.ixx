module;
#include <string>

export module sys_scan.scanner;
import sys_scan.types;
import sys_scan.coro;

export namespace sys_scan {

class Scanner {
public:
    virtual ~Scanner() = default;

    virtual std::string name() const = 0;
    virtual std::string description() const = 0;

    // The Core Architectural Change:
    // 1. Returns a Generator (Pull model)
    // 2. No ScanContext (Dependencies injected via constructor)
    virtual Generator<Finding> scan() = 0;
};

}
