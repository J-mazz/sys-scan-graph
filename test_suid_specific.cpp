#include <sys/stat.h>
#include <iostream>
#include <cstring>

bool has_suid_or_sgid(const char* path) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        std::cout << "lstat failed for " << path << ": " << strerror(errno) << std::endl;
        return false;
    }
    bool has_suid = (st.st_mode & S_ISUID);
    bool has_sgid = (st.st_mode & S_ISGID);
    std::cout << path << ": mode=" << std::oct << st.st_mode << std::dec 
              << " SUID=" << has_suid << " SGID=" << has_sgid << std::endl;
    return has_suid || has_sgid;
}

int main() {
    // Test the specific files that should be found
    const char* test_files[] = {
        "/usr/bin/passwd",
        "/usr/bin/sudo", 
        "/usr/bin/chsh",
        "/usr/bin/ssh-agent"
    };
    
    for (const char* path : test_files) {
        has_suid_or_sgid(path);
    }
    return 0;
}
