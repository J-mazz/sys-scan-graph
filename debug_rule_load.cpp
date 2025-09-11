#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>
#include "../src/core/RuleEngine.h"

int main() {
    sys_scan::RuleEngine engine;
    
    // Create temp directory
    std::filesystem::create_directory("temp_rules");
    
    // Create rule file with bad regex
    std::ofstream rule_file("temp_rules/bad_regex.rule");
    rule_file << "id=bad_regex_rule\n";
    rule_file << "field=description\n";
    rule_file << "regex=[invalid regex\n";
    rule_file << "severity_override=low\n";
    rule_file.close();
    
    std::string warnings;
    engine.load_dir("temp_rules", warnings);
    
    std::cout << "Warnings string: '" << warnings << "'" << std::endl;
    std::cout << "Warnings vector size: " << engine.warnings().size() << std::endl;
    
    for (const auto& w : engine.warnings()) {
        std::cout << "Warning: rule_id='" << w.rule_id << "', code='" << w.code << "', detail='" << w.detail << "'" << std::endl;
    }
    
    // Cleanup
    std::filesystem::remove_all("temp_rules");
    
    return 0;
}
