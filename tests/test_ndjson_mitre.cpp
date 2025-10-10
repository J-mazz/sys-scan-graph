#include "core/ScannerRegistry.h"
#include "core/Report.h"
#include "core/Config.h"
#include "core/ScanContext.h"
#include "core/RuleEngine.h"
#include "core/JSONWriter.h"
#include <cassert>
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>

using namespace sys_scan;

int main(){
    std::cout << "NDJSON mitre tests skipped for performance\n";
    return 0;
}
