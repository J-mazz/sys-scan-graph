#include "Config.h"
#include <algorithm>

namespace sys_scan {
static Config global_cfg; 
Config& config(){ return global_cfg; }
void set_config(const Config& c){ global_cfg = c; }

int severity_rank(const std::string& sev){
    std::string s=sev; std::transform(s.begin(),s.end(),s.begin(),::tolower);
    if(s=="info") return 0;
    if(s=="low") return 1;
    if(s=="medium") return 2;
    if(s=="high") return 3;
    if(s=="critical") return 4;
    if(s=="error") return 5;
    return 0;
}
}
