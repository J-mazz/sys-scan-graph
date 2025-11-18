#include "RuleEngine.h"
#include "Config.h"
#include "Logging.h"
#include "Utils.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <regex>
#include <unordered_set>
#include <unordered_map>

namespace fs = std::filesystem;
namespace sys_scan {

// Thread-safe function-local static instance to avoid data-race on first use
RuleEngine& rule_engine() {
    static RuleEngine instance;
    return instance;
}

// ============================================================================
// REFACTORED HELPER FUNCTIONS
// ============================================================================

namespace {
    // Parse a single line of a rule file into key-value pair
    struct KeyValue {
        std::string key;
        std::string value;
        bool valid = false;
    };

    KeyValue parse_rule_line(const std::string& line) {
        std::string trimmed = utils::trim(line);

        // Skip empty lines and comments
        if (trimmed.empty() || trimmed[0] == '#') {
            return {};
        }

        // Find '=' separator
        auto pos = trimmed.find('=');
        if (pos == std::string::npos) {
            return {};
        }

        KeyValue kv;
        kv.key = utils::trim(trimmed.substr(0, pos));
        kv.value = utils::trim(trimmed.substr(pos + 1));
        kv.valid = true;
        return kv;
    }

    // Parse indexed condition key (e.g., "condition3.field" -> {"3", "field"})
    struct ConditionKey {
        std::string index;
        std::string attribute;
        bool valid = false;
    };

    ConditionKey parse_condition_key(const std::string& key) {
        auto dot = key.find('.');
        if (dot == std::string::npos) {
            return {};
        }

        std::string prefix = key.substr(0, dot);
        if (prefix.rfind("condition", 0) != 0) {
            return {};
        }

        ConditionKey ck;
        ck.index = prefix.substr(9); // Skip "condition"
        if (ck.index.empty()) {
            ck.index = "0";
        }
        ck.attribute = key.substr(dot + 1);
        ck.valid = true;
        return ck;
    }

    // Process a parsed key-value into rule structure
    void apply_rule_field(const std::string& key, const std::string& value,
                          Rule& rule, bool& has_id,
                          std::unordered_map<std::string, RuleCondition>& indexed,
                          std::ostringstream& warn,
                          std::vector<RuleWarning>& warnings) {
        if (key == "id") {
            rule.id = value;
            has_id = true;
        }
        else if (key == "rule_version") {
            try {
                rule.version = std::stoi(value);
            } catch(...) {
                rule.version = 0;
            }
            if (rule.version != 1) {
                warn << rule.id << ":unsupported_version=" << value << ";";
                warnings.push_back({rule.id, "unsupported_version", value});
            }
        }
        else if (key == "scope") {
            rule.scope = value;
        }
        else if (key == "severity" || key == "severity_override") {
            rule.severity_override = value;
        }
        else if (key == "mitre") {
            rule.mitre = value;
        }
        else if (key == "logic") {
            if (value == "any" || value == "ANY") {
                rule.logic_any = true;
            }
        }
        // Legacy single-condition fields
        else if (key == "field") {
            rule.legacy_field = value;
        }
        else if (key == "contains") {
            rule.legacy_contains = value;
        }
        else if (key == "equals") {
            rule.legacy_equals = value;
        }
        else if (key == "regex") {
            rule.legacy_regex = value;
        }
        // New multi-condition format: conditionN.attribute
        else {
            auto ck = parse_condition_key(key);
            if (ck.valid) {
                RuleCondition& rc = indexed[ck.index];

                if (ck.attribute == "field") {
                    rc.field = value;
                }
                else if (ck.attribute == "contains") {
                    rc.contains = value;
                }
                else if (ck.attribute == "equals") {
                    rc.equals = value;
                }
                else if (ck.attribute == "regex") {
                    rc.regex = value;
                }
            }
        }
    }

    // Convert indexed conditions map into sorted vector
    void finalize_conditions(Rule& rule,
                            const std::unordered_map<std::string, RuleCondition>& indexed) {
        if (!indexed.empty()) {
            // Sort conditions by numeric index for determinism
            std::vector<std::pair<int, RuleCondition>> tmp;
            tmp.reserve(indexed.size());

            for (const auto& kv : indexed) {
                int n = 0;
                try {
                    n = std::stoi(kv.first);
                } catch(...) {
                    // Use 0 if parsing fails
                }
                tmp.emplace_back(n, kv.second);
            }

            std::sort(tmp.begin(), tmp.end(),
                     [](const auto& a, const auto& b) { return a.first < b.first; });

            for (auto& pr : tmp) {
                rule.conditions.push_back(std::move(pr.second));
            }
        }
        // Fallback to legacy single condition if present
        else if (!rule.legacy_field.empty() || !rule.legacy_contains.empty() ||
                 !rule.legacy_equals.empty() || !rule.legacy_regex.empty()) {
            RuleCondition rc;
            rc.field = rule.legacy_field;
            rc.contains = rule.legacy_contains;
            rc.equals = rule.legacy_equals;
            rc.regex = rule.legacy_regex;
            rule.conditions.push_back(std::move(rc));
        }
    }

    // Validate and compile regex patterns in conditions
    void validate_conditions(Rule& rule,
                            std::ostringstream& warn,
                            std::vector<RuleWarning>& warnings) {
        if (rule.conditions.empty()) {
            warn << rule.id << ":no_conditions;";
            warnings.push_back({rule.id, "no_conditions", ""});
            return;
        }

        // Pre-validate regex patterns
        for (auto& c : rule.conditions) {
            if (!c.regex.empty()) {
                // Check regex length
                if (c.regex.size() > RuleEngine::MAX_REGEX_LENGTH) {
                    warnings.push_back({rule.id, "regex_too_long",
                                       std::to_string(c.regex.size())});
                    warn << rule.id << ":regex_too_long;";
                    c.regex.clear();
                    continue;
                }

                // Try to compile regex
                try {
                    c.compiled.emplace(c.regex, std::regex::ECMAScript);
                } catch(const std::exception&) {
                    warn << rule.id << ":bad_regex;";
                    warnings.push_back({rule.id, "bad_regex", c.regex});
                    c.regex.clear();
                    c.compiled.reset();
                }
            }
        }

        // Limit number of conditions per rule
        if (rule.conditions.size() > RuleEngine::MAX_CONDITIONS_PER_RULE) {
            warnings.push_back({rule.id, "too_many_conditions",
                               std::to_string(rule.conditions.size())});
            warn << rule.id << ":too_many_conditions;";
            rule.conditions.resize(RuleEngine::MAX_CONDITIONS_PER_RULE);
        }
    }

    // Parse a single rule file
    std::optional<Rule> parse_rule_file(const fs::path& path,
                                        std::ostringstream& warn,
                                        std::vector<RuleWarning>& warnings) {
        std::ifstream ifs(path);
        if (!ifs) {
            return std::nullopt;
        }

        Rule rule;
        bool has_id = false;
        std::unordered_map<std::string, RuleCondition> indexed;
        std::string line;

        while (std::getline(ifs, line)) {
            auto kv = parse_rule_line(line);
            if (!kv.valid) {
                continue;
            }

            apply_rule_field(kv.key, kv.value, rule, has_id,
                           indexed, warn, warnings);
        }

        // Skip rules without ID
        if (!has_id) {
            return std::nullopt;
        }

        // Convert indexed conditions to vector
        finalize_conditions(rule, indexed);

        // Validate all conditions
        validate_conditions(rule, warn, warnings);

        return rule;
    }

    // Collect all .rule files from directory
    std::vector<fs::path> collect_rule_files(const std::string& dir) {
        std::vector<fs::path> files;
        std::error_code ec;

        for (auto& ent : fs::directory_iterator(dir,
                                               fs::directory_options::skip_permission_denied,
                                               ec)) {
            if (ec) break;
            if (!ent.is_regular_file()) continue;

            auto p = ent.path();
            if (p.extension() != ".rule") continue;

            files.push_back(p);
        }

        std::sort(files.begin(), files.end());
        return files;
    }

} // anonymous namespace

// ============================================================================
// PUBLIC API (REFACTORED)
// ============================================================================

void RuleEngine::load_dir(const std::string& dir, std::string& warning_out) {
    rules_.clear();
    warnings_.clear();

    if (dir.empty()) {
        return;
    }

    // Check if directory exists
    std::error_code ec;
    if (!fs::exists(dir, ec)) {
        warning_out = "rules_dir_missing";
        warnings_.push_back({"", "rules_dir_missing", ""});
        return;
    }

    std::ostringstream warn;
    auto files = collect_rule_files(dir);

    for (const auto& path : files) {
        // Check rules limit
        if (rules_.size() >= MAX_RULES) {
            warnings_.push_back({"", "max_rules_exceeded", std::to_string(MAX_RULES)});
            warn << "global:max_rules_exceeded=" << MAX_RULES << ";";
            break;
        }

        // Parse rule file
        auto rule_opt = parse_rule_file(path, warn, warnings_);
        if (rule_opt.has_value()) {
            rules_.push_back(std::move(*rule_opt));
        }
    }

    warning_out = warn.str();
}

std::string RuleEngine::warnings_aggregated() const {
    std::ostringstream oss; for(const auto& w: warnings_){ if(!w.rule_id.empty()) oss << w.rule_id << ':'; if(!w.code.empty()) oss << w.code; if(!w.detail.empty()) oss << '=' << w.detail; oss << ';'; } return oss.str();
}

static bool match_condition(const RuleCondition& rc, const Finding& f){
	const std::string* target=nullptr; std::string desc;
	if(rc.field.empty()) { desc = f.description; target=&desc; }
	else if(rc.field=="id") target=&f.id; else if(rc.field=="title") target=&f.title; else if(rc.field=="description") { desc = f.description; target=&desc; }
	else {
		auto it = f.metadata.find(rc.field); if(it!=f.metadata.end()) target=&it->second; else return false;
	}
	// Guardrail: a condition with only a field selector and no constraints should not auto-match everything.
	if(rc.contains.empty() && rc.equals.empty() && !rc.compiled && rc.regex.empty()) return false;
	if(!rc.contains.empty() && target->find(rc.contains)==std::string::npos) return false;
	if(!rc.equals.empty() && *target != rc.equals) return false;
	if(rc.compiled) { if(!std::regex_search(*target, *rc.compiled)) return false; }
	return true;
}

void RuleEngine::apply(const std::string& scanner, Finding& f) const {
	if(rules_.empty()) return;
	for(const auto& r: rules_){
		if(!r.scope.empty() && r.scope!="*" && r.scope != scanner) continue;
		if(r.conditions.empty()) continue; // nothing to evaluate
		bool matched=false; if(r.logic_any){ for(const auto& c: r.conditions){ if(match_condition(c,f)){ matched=true; break; } } } else { matched=true; for(const auto& c: r.conditions){ if(!match_condition(c,f)){ matched=false; break; } } }
		if(!matched) continue;
		if(!r.severity_override.empty()) f.severity = severity_from_string(r.severity_override);
		if(!r.mitre.empty()) {
			auto & mt = f.metadata["mitre_techniques"];
			// Build set of existing tokens preserving insertion order via vector+set
			auto split = [](const std::string& s){ std::vector<std::string> out; std::string cur; for(char c: s){ if(c==','){ if(!cur.empty()) { out.push_back(utils::trim(cur)); cur.clear(); } } else cur.push_back(c);} if(!cur.empty()){ out.push_back(utils::trim(cur)); } return out; };
			std::vector<std::string> existing = split(mt);
			std::unordered_set<std::string> seen(existing.begin(), existing.end());
			std::vector<std::string> added = split(r.mitre);
			for(const auto& tok : added){ if(tok.empty()) continue; if(!seen.count(tok)){ existing.push_back(tok); seen.insert(tok); } }
			// Rebuild canonical comma-separated list
			std::ostringstream rebuilt; for(size_t i=0;i<existing.size();++i){ if(i) rebuilt << ','; rebuilt << existing[i]; }
			mt = rebuilt.str();
		}
	}
}

}
