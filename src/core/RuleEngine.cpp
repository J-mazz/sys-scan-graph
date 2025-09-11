// Enhanced rule engine implementation
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

static RuleEngine* g_engine=nullptr;
RuleEngine& rule_engine(){ if(!g_engine) g_engine = new RuleEngine(); return *g_engine; }

// Parse rule file format supporting both legacy single-condition keys and new multi-condition keys.
// New multi-condition keys use numbered suffix: conditionN.field / conditionN.contains / conditionN.equals / conditionN.regex
// logic=any|all, scope=<scanner or *> , severity=, mitre=
void RuleEngine::load_dir(const std::string& dir, std::string& warning_out){
	rules_.clear(); warnings_.clear(); if(dir.empty()) return; std::error_code ec; if(!fs::exists(dir, ec)){ warning_out="rules_dir_missing"; warnings_.push_back({"","rules_dir_missing",""}); return; }
	std::ostringstream warn; // legacy aggregation builder
	std::vector<fs::path> files; for(auto& ent: fs::directory_iterator(dir, fs::directory_options::skip_permission_denied, ec)){
		if(ec) break; if(!ent.is_regular_file()) continue; auto p = ent.path(); if(p.extension() != ".rule") continue; files.push_back(p);
	}
	std::sort(files.begin(), files.end());
	for(const auto& p: files){
		if(rules_.size() >= MAX_RULES){ warnings_.push_back({"","max_rules_exceeded", std::to_string(MAX_RULES)}); warn << "global:max_rules_exceeded="<<MAX_RULES<<";"; break; }
		std::ifstream ifs(p); if(!ifs) continue; Rule r; bool has_id=false; std::string line; std::unordered_map<std::string, RuleCondition> indexed; // key: N
		while(std::getline(ifs,line)){
			line=utils::trim(line); if(line.empty()||line[0]=='#') continue; auto pos=line.find('='); if(pos==std::string::npos) continue; auto k=utils::trim(line.substr(0,pos)); auto v=utils::trim(line.substr(pos+1));
			if(k=="id"){ r.id=v; has_id=true; }
			else if(k=="rule_version") { try { r.version = std::stoi(v); } catch(...) { r.version = 0; } if(r.version!=1) { warn << r.id << ":unsupported_version=" << v << ";"; warnings_.push_back({r.id, "unsupported_version", v}); } }
			else if(k=="scope") r.scope=v; else if(k=="severity"||k=="severity_override") r.severity_override=v; else if(k=="mitre") r.mitre=v;
			else if(k=="logic") { if(v=="any"||v=="ANY") r.logic_any=true; }
			else if(k=="field") r.legacy_field=v; else if(k=="contains") r.legacy_contains=v; else if(k=="equals") r.legacy_equals=v; else if(k=="regex") r.legacy_regex=v; // legacy single
			else {
				// conditionN.key
				auto dot = k.find('.'); if(dot!=std::string::npos){
					std::string cond = k.substr(0,dot); std::string attr = k.substr(dot+1);
					if(cond.rfind("condition",0)==0){
						std::string idx = cond.substr(9); if(idx.empty()) idx="0";
						RuleCondition & rc = indexed[idx];
						if(attr=="field") rc.field=v; else if(attr=="contains") rc.contains=v; else if(attr=="equals") rc.equals=v; else if(attr=="regex") rc.regex=v;
					}
				}
			}
		}
		if(!has_id) continue; // skip anonymous
		// Move indexed conditions into vector (sorted by index numeric for determinism)
		if(!indexed.empty()){
			std::vector<std::pair<int,RuleCondition>> tmp; tmp.reserve(indexed.size());
			for(auto& kv : indexed){ int n=0; try{ n=std::stoi(kv.first);}catch(...){ } tmp.emplace_back(n, kv.second); }
			std::sort(tmp.begin(), tmp.end(), [](auto&a, auto&b){ return a.first < b.first; });
			for(auto& pr: tmp){ r.conditions.push_back(std::move(pr.second)); }
		} else if(!r.legacy_field.empty() || !r.legacy_contains.empty() || !r.legacy_equals.empty() || !r.legacy_regex.empty()) {
			RuleCondition rc; rc.field = r.legacy_field; rc.contains = r.legacy_contains; rc.equals = r.legacy_equals; rc.regex = r.legacy_regex; r.conditions.push_back(std::move(rc));
		}
		if(r.conditions.empty()) { warn << r.id << ":no_conditions;"; warnings_.push_back({r.id, "no_conditions", ""}); }
		else {
			// pre-validate regex
			for(auto& c: r.conditions){ if(!c.regex.empty()){ if(c.regex.size() > MAX_REGEX_LENGTH){ warnings_.push_back({r.id, "regex_too_long", std::to_string(c.regex.size())}); warn << r.id << ":regex_too_long;"; c.regex.clear(); continue; } try { c.compiled.emplace(c.regex, std::regex::ECMAScript); } catch(const std::exception&){ warn << r.id << ":bad_regex;"; warnings_.push_back({r.id, "bad_regex", c.regex}); c.regex.clear(); c.compiled.reset(); } } }
			if(r.conditions.size() > MAX_CONDITIONS_PER_RULE){ warnings_.push_back({r.id, "too_many_conditions", std::to_string(r.conditions.size())}); warn << r.id << ":too_many_conditions;"; // trim extra for safety
				r.conditions.resize(MAX_CONDITIONS_PER_RULE);
			}
		}
		rules_.push_back(std::move(r));
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
