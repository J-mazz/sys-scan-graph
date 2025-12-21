module;
#include <vector>
#include <span>
#include <variant>

export module sys_scan.ui.report_parser;

import sys_scan.ui.types;

export namespace sys_scan::ui {

    struct ReportParser {
        static std::variant<std::vector<Finding>, ParseError> parse_json(std::span<const char> json_data);
    };

}
