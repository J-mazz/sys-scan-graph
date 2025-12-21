#include "agent_interface.h"
#include <cstdio>
#include <array>
#include <memory>
#include <stdexcept>
#include <sstream>
#include <thread>
#include <unistd.h>
#include <sys/wait.h>

namespace SysScanUI {

AgentInterface::AgentInterface(const std::string& agent_path)
    : agent_path_(agent_path) {
    // Check if agent is available
    std::string check_cmd = "command -v " + agent_path + " >/dev/null 2>&1";
    available_ = (system(check_cmd.c_str()) == 0);
}

AgentInterface::~AgentInterface() = default;

bool AgentInterface::is_available() const {
    return available_;
}

std::string AgentInterface::execute_agent_command(const std::string& command) {
    std::array<char, 128> buffer;
    std::string result;

    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        return "Error: Failed to execute agent command";
    }

    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }

    int status = pclose(pipe);
    if (status != 0) {
        return "Error: Agent command failed with status " + std::to_string(status);
    }

    return result;
}

std::string AgentInterface::query(const std::string& question, const std::string& report_path) {
    if (!available_) {
        return "Error: sys-scan-graph agent not available. Please install sys-scan-graph.";
    }

    // Build the agent query command
    // The agent can be queried by running analysis with specific prompts
    std::ostringstream cmd;
    cmd << agent_path_ << " analyze"
        << " --report " << report_path
        << " --query '" << question << "'"
        << " 2>&1";

    return execute_agent_command(cmd.str());
}

void AgentInterface::query_async(const std::string& question,
                                  const std::string& report_path,
                                  std::function<void(const std::string&)> callback) {
    std::thread([this, question, report_path, callback]() {
        std::string result = query(question, report_path);
        callback(result);
    }).detach();
}

} // namespace SysScanUI
