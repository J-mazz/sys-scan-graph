module;
#include "types.h"

export module sys_scan.ui.types;

export namespace sys_scan::ui {

    // Re-export header-defined symbols into this module
    using Severity = ::sys_scan::ui::Severity;
    using Finding = ::sys_scan::ui::Finding;
    using ParseError = ::sys_scan::ui::ParseError;


}

// Keep moc-generated code out of the exported module interface

