#include "KernelParamScanner.h"
#include "../core/Report.h"
#include <fstream>
#include <map>

namespace sys_scan {

void KernelParamScanner::scan(Report& report) {
    struct Item { std::string path; std::string desired; std::string desc; std::string severity; };
    std::vector<Item> items = {
        {"/proc/sys/kernel/randomize_va_space", "2", "ASLR should be full (2)", "medium"},
        {"/proc/sys/kernel/kptr_restrict", "1", "Kernel pointer addresses restricted", "low"},
        {"/proc/sys/net/ipv4/conf/all/rp_filter", "1", "Reverse path filtering", "low"},
        {"/proc/sys/net/ipv4/ip_forward", "0", "IP forwarding disabled unless a router", "info"}
    };
    for(auto& it: items){
        std::ifstream ifs(it.path);
        if(!ifs){
            report.add_warning(this->name(), WarnCode::ParamUnreadable, it.path);
            continue;
        }
        std::string val; std::getline(ifs, val);
        Finding f; f.id = it.path; f.title = it.path; f.severity = (val==it.desired?Severity::Info:severity_from_string(it.severity)); f.description = it.desc; f.metadata["current"] = val; f.metadata["desired"] = it.desired; if(val!=it.desired) f.metadata["status"]="mismatch"; report.add_finding(this->name(), std::move(f));
    }
}

}
