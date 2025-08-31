#include "KernelParamScanner.h"
#include "../core/ScanContext.h"
#include "../core/Report.h"
#include "../core/Severity.h"
#include <fstream>
#include <map>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>

namespace sys_scan {

// Static configuration to avoid recreation on each scan
struct KernelParamItem {
    const char* path;
    const char* desired;
    const char* desc;
    Severity severity_level;
};

// Pre-defined kernel parameters with optimized data structure
static const KernelParamItem KERNEL_PARAMS[] = {
    {"/proc/sys/kernel/randomize_va_space", "2", "ASLR should be full (2)", Severity::Medium},
    {"/proc/sys/kernel/kptr_restrict", "1", "Kernel pointer addresses restricted", Severity::Low},
    {"/proc/sys/net/ipv4/conf/all/rp_filter", "1", "Reverse path filtering", Severity::Low},
    {"/proc/sys/net/ipv4/ip_forward", "0", "IP forwarding disabled unless a router", Severity::Info}
};

static const size_t KERNEL_PARAMS_COUNT = sizeof(KERNEL_PARAMS) / sizeof(KERNEL_PARAMS[0]);

// Optimized file reading function using POSIX I/O for better performance
static bool read_kernel_param(const char* path, std::string& value) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        return false;
    }

    char buffer[256]; // Kernel params are typically small
    ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);

    if (bytes_read <= 0) {
        return false;
    }

    // Trim whitespace and null-terminate
    buffer[bytes_read] = '\0';
    char* end = buffer + bytes_read - 1;
    while (end > buffer && (*end == '\n' || *end == ' ' || *end == '\t')) {
        *end-- = '\0';
    }

    value.assign(buffer);
    return true;
}

void KernelParamScanner::scan(ScanContext& context) {
    // Pre-allocate findings vector to avoid reallocations
    std::vector<Finding> findings;
    findings.reserve(KERNEL_PARAMS_COUNT);

    // Process each kernel parameter with optimized I/O
    for (size_t i = 0; i < KERNEL_PARAMS_COUNT; ++i) {
        const auto& item = KERNEL_PARAMS[i];
        std::string current_value;

        if (!read_kernel_param(item.path, current_value)) {
            // File unreadable - add warning
            context.report.add_warning(this->name(), WarnCode::ParamUnreadable, item.path);
            continue;
        }

        // Create finding with optimized string operations
        Finding f;
        f.id = item.path;
        f.title = item.path;
        f.description = item.desc;

        // Determine severity based on value match
        if (current_value == item.desired) {
            f.severity = Severity::Info;
        } else {
            f.severity = item.severity_level;
            f.metadata["status"] = "mismatch";
        }

        // Add metadata with optimized string operations
        f.metadata["current"] = std::move(current_value);
        f.metadata["desired"] = item.desired;

        findings.push_back(std::move(f));
    }

    // Add all findings to report in batch
    for (auto& finding : findings) {
        context.report.add_finding(this->name(), std::move(finding));
    }
}

}
