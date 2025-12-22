#pragma once

#include <variant>
#include <vector>
#include <span>
#include "types.h"

namespace sys_scan::ui {

struct ReportParser {
    static std::variant<std::vector<Finding>, ParseError> parse_json(std::span<const char> json_data);
};

} // namespace sys_scan::ui
