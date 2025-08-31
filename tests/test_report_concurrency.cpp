#include "core/Report.h"
#include "core/Scanner.h"
#include <thread>
#include <vector>
#include <cassert>
#include <iostream>

using namespace sys_scan;

int main(){
    Report report;
    const std::string scannerName = "concurrent";
    report.start_scanner(scannerName);
    const int threads = 16;
    const int per_thread = 1000; // 16k findings total
    std::vector<std::thread> workers;
    workers.reserve(threads);
    for(int t=0;t<threads;++t){
        workers.emplace_back([&report, scannerName, per_thread]{
            for(int i=0;i<per_thread;++i){
                Finding f; f.id = "stress"; f.severity = Severity::Info; f.title = "stress test"; f.description = "concurrency"; f.base_severity_score = 0; // will be set in add_finding
                report.add_finding(scannerName, std::move(f));
            }
        });
    }
    for(auto& th: workers) th.join();
    report.end_scanner(scannerName);

    size_t expected = static_cast<size_t>(threads) * per_thread;
    size_t actual = report.total_findings();
    if(actual != expected){
        std::cerr << "Concurrency test failed: expected " << expected << " findings, got " << actual << "\n";
        return 1;
    }
    std::cout << "Concurrency test passed: " << actual << " findings." << std::endl;
    return 0;
}
