# Migration Steps

1. Copy this entire directory into `sys-scan-graph/ui/`.
2. Delete the `.git` folder from `sys-scan-graph/ui/` if you don't want nested repositories.
3. Add `ui/` to the root `.gitignore` if you want to keep UI as external, OR `git add ui/` to commit into the monorepo directly.
4. Update `sys-scan-graph/pyproject.toml` if you want packaging metadata for the UI included in releases.
5. Run the `build_release.sh` script from the repository root to build Python and C++ components.

Notes
- Ensure system dependencies (Qt6, Vulkan, clang) are available on CI and developer machines.
- Consider adding `ui/` as a submodule if you want independent lifecycle management.
