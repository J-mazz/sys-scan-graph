module;
#include <string>
#include <cstdint>
#include <map>
#include <vector>
#include <algorithm>
#include <cctype>
#include <utility>
export module sys_scan.types;

export namespace sys_scan {

// --- Severity ---
enum class Severity : uint8_t {
    Info = 0,
    Low,
    Medium,
    High,
    Critical,
    Error
};

inline const char* severity_to_string(Severity s){
    switch(s){
        using enum Severity;
        case Info: return "info";
        case Low: return "low";
        case Medium: return "medium";
        case High: return "high";
        case Critical: return "critical";
        case Error: return "error";
    }
    return "info";
}

inline Severity severity_from_string(const std::string& in){
    std::string s; s.reserve(in.size());
    for(char c: in){ s.push_back((char)std::tolower((unsigned char)c)); }
    if(s=="info") return Severity::Info;
    if(s=="low") return Severity::Low;
    if(s=="medium") return Severity::Medium;
    if(s=="high") return Severity::High;
    if(s=="critical") return Severity::Critical;
    if(s=="error") return Severity::Error;
    return Severity::Info;
}

inline int severity_risk_score(Severity s){
    switch(s){
        using enum Severity;
        case Info: return 10;
        case Low: return 30;
        case Medium: return 50;
        case High: return 70;
        case Critical: return 90;
        case Error: return 80;
    }
    return 10;
}

// --- Finding ---
struct Finding {
    std::string id;
    std::string title;
    Severity severity = Severity::Info;
    std::string description;
    std::map<std::string, std::string> metadata;
    int base_severity_score = 0;
    bool operational_error = false;
};

// --- WarnCode ---
enum class WarnCode {
    DecompressFail,
    ParamUnreadable,
    ProcUnreadableStatus,
    ProcUnreadableCmdline,
    ProcExeSymlinkUnreadable,
    NetFileUnreadable,
    WalkError,
    MountsUnreadable,
    Generic
};

// C++23: Explicit Object Parameter (Deducing This)
struct FindingBuilder {
    Finding f;

    template <typename Self>
    Self&& set_id(this Self&& self, std::string id) {
        self.f.id = std::move(id);
        return std::forward<Self>(self);
    }

    template <typename Self>
    Self&& set_title(this Self&& self, std::string title) {
        self.f.title = std::move(title);
        return std::forward<Self>(self);
    }

    template <typename Self>
    Self&& set_severity(this Self&& self, Severity sev) {
        self.f.severity = sev;
        return std::forward<Self>(self);
    }

    Finding build() { return std::move(f); }
};

}
