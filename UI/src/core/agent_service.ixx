module;
#include "agent_service.h"

export module sys_scan.ui.agent;

// Re-export the header-defined symbol into the module
export namespace sys_scan::ui {
    using AgentService = ::sys_scan::ui::AgentService;
}

