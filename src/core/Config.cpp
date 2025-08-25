#include "Config.h"
#include <algorithm>
#include "Severity.h"

namespace sys_scan {
static Config global_cfg; 
Config& config(){ return global_cfg; }
void set_config(const Config& c){ global_cfg = c; }

// legacy wrapper provided inline in Severity.h now; keep no-op definition out to avoid ODR issues
int severity_rank(const std::string& sev); // forward declaration only (definition inline)
}
