#include <iostream>
#include <dirent.h>
#include <cstring>
#include <sys/stat.h>

int main() {
    const char* dir_path = "/usr/bin";
    DIR* dir = opendir(dir_path);
    if (!dir) {
        std::cout << "Failed to open " << dir_path << std::endl;
        return 1;
    }

    struct dirent* entry;
    int count = 0;
    bool found_passwd = false;
    bool found_sudo = false;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        
        if (strcmp(entry->d_name, "passwd") == 0) {
            found_passwd = true;
            std::cout << "Found passwd at count " << count << std::endl;
        }
        if (strcmp(entry->d_name, "sudo") == 0) {
            found_sudo = true;
            std::cout << "Found sudo at count " << count << std::endl;
        }
        count++;
        
        if (count > 3000) break; // Safety break
    }

    closedir(dir);
    std::cout << "Total files processed: " << count << std::endl;
    std::cout << "Found passwd: " << found_passwd << std::endl;
    std::cout << "Found sudo: " << found_sudo << std::endl;
    
    return 0;
}
