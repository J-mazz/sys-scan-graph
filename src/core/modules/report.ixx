module;
#include <vector>
#include <string>
#include <mutex>
#include <map>
#include <chrono>
#include <utility>
#if __has_include(<mdspan>)
#include <mdspan>
#define SYS_SCAN_HAS_MDSPAN 1
#elif __has_include(<experimental/mdspan>)
#include <experimental/mdspan>
#define SYS_SCAN_HAS_EXPERIMENTAL_MDSPAN 1
#endif

export module sys_scan.report;
import sys_scan.types;
import sys_scan.coro;

export namespace sys_scan {

struct ScanResult {
    std::string scanner_name;
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;
    std::vector<Finding> findings;
};

class Report {
public:
    // Thread-safe consumption of a scanner's generator
    void consume(const std::string& scanner_name, Generator<Finding> generator) {
        ScanResult result;
        result.scanner_name = scanner_name;
        result.start_time = std::chrono::system_clock::now();

        // Iterate the coroutine - this suspends/resumes execution
        for (const auto& finding : generator) {
            result.findings.push_back(finding);
        }

        result.end_time = std::chrono::system_clock::now();
        
        std::lock_guard<std::mutex> lock(mutex_);
        results_.push_back(std::move(result));
    }

    void add_warning(const std::string& scanner, const std::string& msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        warnings_.emplace_back(scanner, msg);
    }

    void add_error(const std::string& scanner, const std::string& msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        errors_.emplace_back(scanner, msg);
    }

    // Read-only accessors
    const std::vector<ScanResult>& results() const { return results_; }
    const std::vector<std::pair<std::string,std::string>>& warnings() const { return warnings_; }
    const std::vector<std::pair<std::string,std::string>>& errors() const { return errors_; }

private:
    std::vector<ScanResult> results_;
    std::vector<std::pair<std::string,std::string>> warnings_;
    std::vector<std::pair<std::string,std::string>> errors_;
    mutable std::mutex mutex_;
};

// C++23: std::mdspan and multidimensional subscript
class RiskHeatmap {
    std::vector<int> counts;
    size_t rows; // Scanners
    size_t cols; // Severities (0-5)

public:
    RiskHeatmap(size_t num_scanners) : rows(num_scanners), cols(6) {
        counts.resize(rows * cols, 0);
    }

    // Multidimensional subscript operator (C++23)
    int& operator[](size_t scanner_idx, size_t severity_rank) {
        // Create a 2D view over the flat vector on demand
    #if defined(SYS_SCAN_HAS_MDSPAN)
        auto ms = std::mdspan(counts.data(), rows, cols);
        return ms[scanner_idx, severity_rank];
    #elif defined(SYS_SCAN_HAS_EXPERIMENTAL_MDSPAN)
        using extents2d = std::experimental::dextents<size_t, 2>;
        std::experimental::mdspan<int, extents2d> ms(counts.data(), rows, cols);
        return ms(scanner_idx, severity_rank);
    #else
        // Fallback: manual indexing when mdspan is unavailable
        return counts[scanner_idx * cols + severity_rank];
    #endif
    }
};

}
