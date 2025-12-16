module;
#include <coroutine>
#include <string>
#include <vector>
#include <algorithm>

export module sys_scan.scanners.container;
import sys_scan.types;
import sys_scan.scanner;
import sys_scan.coro;
import sys_scan.interfaces;
import sys_scan.config;
import sys_scan.utils;

export namespace sys_scan {

class ContainerScanner : public Scanner {
    const IFileSystem& fs_;
    const Config& config_;

public:
    explicit ContainerScanner(const Config& cfg, const IFileSystem& fs)
        : config_(cfg), fs_(fs) {}

    std::string name() const override { return "containers"; }
    std::string description() const override { return "Detects container environments (Docker, K8s, LXC)"; }

    Generator<Finding> scan() override {
        if (!config_.containers) co_return;

        bool found_container = false;
        std::string container_type = "Unknown";
        std::string evidence;

        // Check 1: .dockerenv
        if (fs_.exists("/.dockerenv")) {
            found_container = true;
            container_type = "Docker";
            evidence = "Found /.dockerenv";
        }

        // Check 2: /proc/1/cgroup
        if (!found_container) {
            std::string cgroup = fs_.read_file("/proc/1/cgroup");
            if (cgroup.find("docker") != std::string::npos) {
                found_container = true;
                container_type = "Docker";
                evidence = "Docker in /proc/1/cgroup";
            } else if (cgroup.find("kubepods") != std::string::npos) {
                found_container = true;
                container_type = "Kubernetes";
                evidence = "Kubepods in /proc/1/cgroup";
            } else if (cgroup.find("lxc") != std::string::npos) {
                found_container = true;
                container_type = "LXC";
                evidence = "LXC in /proc/1/cgroup";
            }
        }

        // Check 3: Environment Variables (via PID 1)
        if (!found_container && fs_.exists("/proc/1/environ")) {
            std::string env = fs_.read_file("/proc/1/environ");
            if (env.find("KUBERNETES_SERVICE_HOST") != std::string::npos) {
                found_container = true;
                container_type = "Kubernetes";
                evidence = "KUBERNETES_SERVICE_HOST in PID 1 env";
            }
        }

        if (found_container) {
            Finding f;
            f.id = "container_detected";
            f.title = "Container Environment Detected";
            f.severity = Severity::Info;
            f.description = "System appears to be running inside a " + container_type + " container";
            f.metadata["type"] = container_type;
            f.metadata["evidence"] = evidence;
            co_yield f;
        }
    }
};

}