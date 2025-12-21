#include "agent_query_builder.h"
#include <algorithm>
#include <sstream>
#include <cctype>

namespace SysScanUI {

std::string AgentQueryBuilder::build_query_command(const std::string& question,
                                                  const std::string& report_path,
                                                  const std::string& agent_path) {
    // Validate inputs
    if (question.empty()) {
        throw std::invalid_argument("Question cannot be empty");
    }
    if (report_path.empty()) {
        throw std::invalid_argument("Report path cannot be empty");
    }
    if (agent_path.empty()) {
        throw std::invalid_argument("Agent path cannot be empty");
    }

    // Escape single quotes in question for shell safety
    std::string escaped_question = question;
    size_t pos = 0;
    while ((pos = escaped_question.find("'", pos)) != std::string::npos) {
        escaped_question.replace(pos, 1, "'\"'\"'");
        pos += 5; // Skip the replacement
    }

    // Build the command
    std::ostringstream cmd;
    cmd << agent_path << " analyze"
        << " --report " << report_path
        << " --query '" << escaped_question << "'"
        << " 2>&1";

    return cmd.str();
}

bool AgentQueryBuilder::validate_question(const std::string& question) {
    if (question.empty()) {
        return false;
    }

    // Check minimum length (reasonable questions should be at least 3 words)
    std::vector<std::string> tokens = tokenize_question(question);
    if (tokens.size() < 3) {
        return false;
    }

    // Check for security-related content
    if (!contains_security_terms(question)) {
        return false;
    }

    // Check for reasonable length (not too long for processing)
    if (question.length() > 1000) {
        return false;
    }

    return true;
}

std::vector<std::string> AgentQueryBuilder::extract_key_terms(const std::string& question) {
    std::vector<std::string> key_terms;
    std::vector<std::string> tokens = tokenize_question(question);

    // Common security terms to look for
    std::vector<std::string> security_keywords = {
        "vulnerability", "vulnerabilities", "exploit", "exploits", "attack", "attacks", 
        "malware", "virus", "viruses", "trojan", "trojans", "rootkit", "rootkits",
        "backdoor", "backdoors", "privilege", "privileges", "escalation", "injection", "injections",
        "xss", "csrf", "sql", "command", "commands", "file", "files", "network", "networks", 
        "port", "ports", "service", "services", "process", "processes", "binary", "binaries",
        "suid", "sgid", "permission", "permissions", "firewall", "selinux", "apparmor", 
        "audit", "audits", "log", "logs", "intrusion", "threat", "threats"
    };

    for (const auto& token : tokens) {
        std::string lower_token = token;
        std::transform(lower_token.begin(), lower_token.end(), lower_token.begin(), ::tolower);

        if (std::find(security_keywords.begin(), security_keywords.end(), lower_token) != security_keywords.end()) {
            key_terms.push_back(token);
        }
    }

    return key_terms;
}

std::string AgentQueryBuilder::determine_response_type(const std::string& question) {
    std::string lower_question = question;
    std::transform(lower_question.begin(), lower_question.end(), lower_question.begin(), ::tolower);

    if (is_summary_question(question)) {
        return "summary";
    } else if (is_investigation_question(question)) {
        return "investigation";
    } else if (lower_question.find("explain") != std::string::npos ||
               lower_question.find("what is") != std::string::npos ||
               lower_question.find("how does") != std::string::npos) {
        return "explanation";
    } else if (lower_question.find("list") != std::string::npos ||
               lower_question.find("show") != std::string::npos) {
        return "list";
    } else {
        return "general";
    }
}

bool AgentQueryBuilder::contains_security_terms(const std::string& question) {
    std::string lower_question = question;
    std::transform(lower_question.begin(), lower_question.end(), lower_question.begin(), ::tolower);

    std::vector<std::string> security_terms = {
        "security", "vulnerable", "exploit", "attack", "malware", "threat",
        "risk", "finding", "scan", "audit", "compliance", "breach"
    };

    for (const auto& term : security_terms) {
        if (lower_question.find(term) != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool AgentQueryBuilder::is_investigation_question(const std::string& question) {
    std::string lower_question = question;
    std::transform(lower_question.begin(), lower_question.end(), lower_question.begin(), ::tolower);

    return lower_question.find("investigate") != std::string::npos ||
           lower_question.find("analyze") != std::string::npos ||
           lower_question.find("examine") != std::string::npos ||
           lower_question.find("check") != std::string::npos;
}

bool AgentQueryBuilder::is_summary_question(const std::string& question) {
    std::string lower_question = question;
    std::transform(lower_question.begin(), lower_question.end(), lower_question.begin(), ::tolower);

    return lower_question.find("summary") != std::string::npos ||
           lower_question.find("overview") != std::string::npos ||
           lower_question.find("status") != std::string::npos ||
           (lower_question.find("what") != std::string::npos &&
            lower_question.find("found") != std::string::npos);
}

std::vector<std::string> AgentQueryBuilder::tokenize_question(const std::string& question) {
    std::vector<std::string> tokens;
    std::istringstream iss(question);
    std::string token;

    while (iss >> token) {
        // Remove punctuation from token
        token.erase(std::remove_if(token.begin(), token.end(),
                    [](char c) { return std::ispunct(c); }), token.end());

        if (!token.empty()) {
            tokens.push_back(token);
        }
    }

    return tokens;
}

} // namespace SysScanUI