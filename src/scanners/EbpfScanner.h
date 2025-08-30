#pragma once
#include "../core/Scanner.h"
#include <memory>
namespace sys_scan {
class EbpfScanner : public Scanner {
public:
    std::string name() const override;
    std::string description() const override;
    void scan(Report& report) override;
};
std::unique_ptr<Scanner> make_ebpf_scanner();
}
