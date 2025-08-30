#include "Config.h"
#include <algorithm>
#include "Severity.h"

namespace sys_scan {
static Config global_cfg; 
Config& config(){ return global_cfg; }
void set_config(const Config& c){ global_cfg = c; }
// Temporary debug instrumentation to trace unexpected config resets during tests.
#ifdef SYS_SCAN_DEBUG_CONFIG
#include <iostream>
void debug_dump_config(const char* tag){
	std::cerr << "[CONFIG] "<<tag<<" no_user_meta="<< (global_cfg.no_user_meta?"true":"false")
			  <<" no_cmdline_meta="<<(global_cfg.no_cmdline_meta?"true":"false")
			  <<" no_hostname_meta="<<(global_cfg.no_hostname_meta?"true":"false") <<"\n";
}
#endif

// legacy wrapper provided inline in Severity.h now; keep no-op definition out to avoid ODR issues
int severity_rank(const std::string& sev); // forward declaration only (definition inline)
}
