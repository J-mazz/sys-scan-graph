module;
#include <nlohmann/json.hpp>
#include <vector>
#include <string>
#include <variant>
#include <span>
#include <QString>

module sys_scan.ui.report_parser;

import sys_scan.ui.types;

using json = nlohmann::json;

namespace sys_scan::ui {

std::variant<std::vector<Finding>, ParseError> ReportParser::parse_json(std::span<const char> json_data) {
    if (json_data.size() == 0) {
        return ParseError{ QStringLiteral("Empty input buffer"), 0 };
    }

    try {
        auto j = json::parse(json_data.begin(), json_data.end());

        std::vector<Finding> results;
        if (j.is_array()) {
            results.reserve(j.size());
            for (const auto& item : j) {
                Finding f;
                f.title = QString::fromStdString(item.value("title", std::string("Unknown")));
                f.severity = static_cast<Severity::Value>(
                    // Map severity string to enum (basic mapping)
                    [&item]() -> int {
                        auto s = item.value("severity", std::string("info"));
                        if (s == "critical") return static_cast<int>(Severity::Critical);
                        if (s == "high") return static_cast<int>(Severity::High);
                        if (s == "medium") return static_cast<int>(Severity::Medium);
                        if (s == "low") return static_cast<int>(Severity::Low);
                        return static_cast<int>(Severity::Info);
                    }()
                );
                f.description = QString::fromStdString(item.value("description", std::string("")));
                f.id = QString::fromStdString(item.value("id", std::string("")));
                results.push_back(std::move(f));
            }
        }

        return results;
    } catch (const json::parse_error& e) {
        return ParseError{ QString::fromStdString(std::string("JSON Syntax Error: ") + e.what()), static_cast<std::size_t>(e.byte) };
    }
}

} // namespace sys_scan::ui
