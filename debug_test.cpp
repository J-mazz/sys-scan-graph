#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <sys/utsname.h>
#include <unistd.h>

namespace fs = std::filesystem;

int main() {
    // Create test directory structure like the test
    auto test_dir = fs::temp_directory_path() / "module_scanner_debug";
    fs::create_directories(test_dir);
    
    // Get actual kernel release
    struct utsname un {};
    uname(&un);
    std::string kernel_release = un.release;
    std::cout << "Actual kernel release: " << kernel_release << std::endl;
    
    // Create directories like the test
    auto kernel_dir = test_dir / "lib" / "modules" / kernel_release;
    auto proc_dir = test_dir / "proc";
    fs::create_directories(kernel_dir);
    fs::create_directories(proc_dir);
    
    // Create mock /proc/modules
    std::ofstream proc_modules(proc_dir / "modules");
    proc_modules << "test_module1 16384 0 - Live 0x0\n";
    proc_modules << "test_module2 16384 0 - Live 0x0\n";
    proc_modules.close();
    
    std::cout << "Created test_dir: " << test_dir << std::endl;
    std::cout << "Created proc/modules at: " << (proc_dir / "modules") << std::endl;
    
    // Check if file exists
    if (fs::exists(proc_dir / "modules")) {
        std::cout << "File exists!" << std::endl;
        std::ifstream in(proc_dir / "modules");
        std::string line;
        while (std::getline(in, line)) {
            std::cout << "Line: " << line << std::endl;
        }
    } else {
        std::cout << "File does not exist!" << std::endl;
    }
    
    // Test the path construction like the scanner
    std::string test_root = test_dir.string();
    std::string proc_path = test_root + "/proc/modules";
    std::cout << "Scanner would look for: " << proc_path << std::endl;
    
    if (fs::exists(proc_path)) {
        std::cout << "Scanner path exists!" << std::endl;
    } else {
        std::cout << "Scanner path does not exist!" << std::endl;
    }
    
    return 0;
}
