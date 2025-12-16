module;
#include <string>
export module sys_scan.utils:helper;

export namespace sys_scan::utils {
    inline std::string in_root(const std::string& root, const std::string& path) {
        if (root.empty() || root == "/") {
            return path;
        }

        if (path.empty()) {
            return root;
        }

        // If caller provides an absolute path, simply prefix root.
        if (!path.empty() && path.front() == '/') {
            return root + path;
        }

        // Relative path: ensure exactly one slash between.
        if (!root.empty() && root.back() == '/') {
            return root + path;
        }
        return root + "/" + path;
    }
}
