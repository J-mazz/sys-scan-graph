#include "result_formatter.h"
#include <algorithm>
#include <sstream>
#include <regex>

namespace SysScanUI {

ResultFormatter::FormattedResult ResultFormatter::format_response(const std::string& raw_response,
                                                                 const std::string& query_type) {
    FormattedResult result;

    // Check for errors first
    if (is_error_response(raw_response)) {
        return format_error(raw_response);
    }

    result.response_type = detect_response_type(raw_response);
    result.title = generate_title(raw_response, query_type);
    result.summary = create_summary(raw_response);
    result.detailed_content = raw_response; // Keep original for detailed view
    result.key_points = extract_key_insights(raw_response);
    result.metadata = extract_metadata(raw_response);
    result.has_error = false;

    return result;
}

ResultFormatter::FormattedResult ResultFormatter::format_error(const std::string& raw_response) {
    FormattedResult result;
    result.has_error = true;
    result.response_type = "error";
    result.title = "Query Error";
    result.error_message = extract_error_message(raw_response);
    result.summary = "The agent encountered an error while processing your query.";
    result.detailed_content = raw_response;

    return result;
}

bool ResultFormatter::is_error_response(const std::string& raw_response) {
    return contains_error_patterns(raw_response);
}

std::vector<std::string> ResultFormatter::extract_key_insights(const std::string& raw_response) {
    std::vector<std::string> insights;

    // Look for numbered or bulleted lists
    std::istringstream iss(raw_response);
    std::string line;
    std::regex bullet_regex("^\\s*[-*•]\\s+(.+)$");
    std::regex number_regex("^\\s*\\d+\\.\\s+(.+)$");

    while (std::getline(iss, line)) {
        std::smatch match;
        if (std::regex_match(line, match, bullet_regex) ||
            std::regex_match(line, match, number_regex)) {
            if (match.size() > 1) {
                insights.push_back(match[1].str());
            }
        }
    }

    // If no bullets found, try to extract sentences with security keywords
    if (insights.empty()) {
        std::vector<std::string> security_keywords = {
            "security", "vulnerability", "vulnerabilities", "risk", "finding", "findings", "issue", "issues", "problem", "problems",
            "recommendation", "recommendations", "critical", "high", "medium", "low", "severity"
        };

        std::istringstream iss2(raw_response);
        while (std::getline(iss2, line)) {
            std::string lower_line = line;
            std::transform(lower_line.begin(), lower_line.end(), lower_line.begin(), ::tolower);

            for (const auto& keyword : security_keywords) {
                if (lower_line.find(keyword) != std::string::npos) {
                    // Clean up the line
                    line.erase(line.begin(), std::find_if(line.begin(), line.end(),
                             [](unsigned char ch) { return !std::isspace(ch); }));
                    line.erase(std::find_if(line.rbegin(), line.rend(),
                             [](unsigned char ch) { return !std::isspace(ch); }).base(), line.end());

                    if (!line.empty() && line.length() > 10) {
                        insights.push_back(line);
                        break;
                    }
                }
            }
        }
    }

    return insights;
}

std::string ResultFormatter::detect_response_type(const std::string& response) {
    std::string lower_response = response;
    std::transform(lower_response.begin(), lower_response.end(), lower_response.begin(), ::tolower);

    if (lower_response.find("summary") != std::string::npos ||
        lower_response.find("overview") != std::string::npos) {
        return "summary";
    } else if (lower_response.find("investigation") != std::string::npos ||
               lower_response.find("analysis") != std::string::npos) {
        return "investigation";
    } else if (lower_response.find("explanation") != std::string::npos ||
               lower_response.find("details") != std::string::npos) {
        return "explanation";
    } else if (lower_response.find("list") != std::string::npos ||
               std::count(response.begin(), response.end(), '\n') > 5) {
        return "list";
    } else {
        return "general";
    }
}

std::string ResultFormatter::generate_title(const std::string& response, const std::string& query_type) {
    // Try to extract a title from the first line
    std::istringstream iss(response);
    std::string first_line;
    if (std::getline(iss, first_line)) {
        // Clean up the line
        first_line.erase(first_line.begin(), std::find_if(first_line.begin(), first_line.end(),
                         [](unsigned char ch) { return !std::isspace(ch); }));
        first_line.erase(std::find_if(first_line.rbegin(), first_line.rend(),
                         [](unsigned char ch) { return !std::isspace(ch); }).base(), first_line.end());

        // If it's a reasonable title length, use it
        if (first_line.length() > 5 && first_line.length() < 100 &&
            !std::all_of(first_line.begin(), first_line.end(), ::isdigit)) {
            return first_line;
        }
    }

    // Fallback titles based on query type
    if (query_type == "summary") {
        return "Security Analysis Summary";
    } else if (query_type == "investigation") {
        return "Investigation Results";
    } else if (query_type == "explanation") {
        return "Detailed Explanation";
    } else {
        return "Query Results";
    }
}

std::string ResultFormatter::create_summary(const std::string& response) {
    // Extract first few sentences or first paragraph
    std::istringstream iss(response);
    std::string summary;
    std::string line;

    // Get first non-empty line
    while (std::getline(iss, line)) {
        line.erase(line.begin(), std::find_if(line.begin(), line.end(),
                 [](unsigned char ch) { return !std::isspace(ch); }));
        line.erase(std::find_if(line.rbegin(), line.rend(),
                 [](unsigned char ch) { return !std::isspace(ch); }).base(), line.end());

        if (!line.empty()) {
            summary = line;
            break;
        }
    }

    // Truncate if too long
    if (summary.length() > 200) {
        summary = summary.substr(0, 197) + "...";
    }

    return summary;
}

std::map<std::string, std::string> ResultFormatter::extract_metadata(const std::string& response) {
    std::map<std::string, std::string> metadata;

    // Look for key-value patterns like "Key: Value"
    std::istringstream iss(response);
    std::string line;
    std::regex kv_regex("^\\s*([^:]+):\\s*(.+)$");

    while (std::getline(iss, line)) {
        std::smatch match;
        if (std::regex_match(line, match, kv_regex)) {
            if (match.size() >= 3) {
                std::string key = match[1].str();
                std::string value = match[2].str();

                // Clean up
                key.erase(key.begin(), std::find_if(key.begin(), key.end(),
                       [](unsigned char ch) { return !std::isspace(ch); }));
                key.erase(std::find_if(key.rbegin(), key.rend(),
                       [](unsigned char ch) { return !std::isspace(ch); }).base(), key.end());

                metadata[key] = value;
            }
        }
    }

    return metadata;
}

bool ResultFormatter::contains_error_patterns(const std::string& response) {
    std::string lower_response = response;
    std::transform(lower_response.begin(), lower_response.end(), lower_response.begin(), ::tolower);

    std::vector<std::string> error_patterns = {
        "error:", "failed", "unable to", "command not found",
        "no such file", "permission denied", "timeout",
        "exception", "fatal", "critical error"
    };

    for (const auto& pattern : error_patterns) {
        if (lower_response.find(pattern) != std::string::npos) {
            return true;
        }
    }

    return false;
}

std::string ResultFormatter::extract_error_message(const std::string& response) {
    // Try to find the first error line
    std::istringstream iss(response);
    std::string line;

    while (std::getline(iss, line)) {
        std::string lower_line = line;
        std::transform(lower_line.begin(), lower_line.end(), lower_line.begin(), ::tolower);

        if (contains_error_patterns(line)) {
            return line;
        }
    }

    // Fallback
    return "An unknown error occurred while processing the query.";
}

} // namespace SysScanUI