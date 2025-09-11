#include <iostream>
#include <dirent.h>
#include <cstring>

#define MAX_PATH_LEN 256
#define MAX_FILES 3000

int list_files(const char* dir_path, char filenames[][MAX_PATH_LEN], int max_files) {
    DIR* dir = opendir(dir_path);
    if (!dir) return 0;

    struct dirent* entry;
    int count = 0;

    while ((entry = readdir(dir)) != NULL && count < max_files) {
        if (entry->d_name[0] == '.') continue;
        std::cout << "Processing file " << count << ": " << entry->d_name << std::endl;
        if (strcmp(entry->d_name, "passwd") == 0) {
            std::cout << "Found passwd!" << std::endl;
        }
        if (strcmp(entry->d_name, "sudo") == 0) {
            std::cout << "Found sudo!" << std::endl;
        }
        strncpy(filenames[count], entry->d_name, MAX_PATH_LEN - 1);
        filenames[count][MAX_PATH_LEN - 1] = '\0';
        count++;
    }

    closedir(dir);
    return count;
}

int main() {
    char (*filenames)[MAX_PATH_LEN] = new char[MAX_FILES][MAX_PATH_LEN];
    int count = list_files("/usr/bin", filenames, MAX_FILES);
    std::cout << "Total files: " << count << std::endl;
    
    // Check if passwd and sudo are in the array
    for (int i = 0; i < count; i++) {
        if (strcmp(filenames[i], "passwd") == 0) {
            std::cout << "passwd found at index " << i << std::endl;
        }
        if (strcmp(filenames[i], "sudo") == 0) {
            std::cout << "sudo found at index " << i << std::endl;
        }
    }
    
    delete[] filenames;
    return 0;
}
