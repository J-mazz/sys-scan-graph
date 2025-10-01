# Refactoring Opportunities

## ArgumentParser: Table-Driven Design

**Status**: Documented for post-v6.0  
**Priority**: Medium (code quality, not functionality)  
**Effort**: ~2-4 hours

### Current State

The `ArgumentParser` class uses a long if-else chain (~320 lines) to dispatch argument handlers:

```cpp
if(arg == "--enable") {
    cfg.enable_scanners = split_csv(value);
} else if(arg == "--disable") {
    cfg.disable_scanners = split_csv(value);
} else if(arg == "--output") {
    cfg.output_file = value;
}
// ... 68 more branches
```

### Proposed: Declarative Table-Driven Approach

Match the scanner registry pattern with a static specification table:

```cpp
struct ArgSpec {
    const char* flag;
    ArgKind kind;
    const char* help;
    std::function<void(Config&, std::string_view)> handler;
};

static const std::array<ArgSpec, 71> ARG_SPECS = {{
    {"--enable", ArgKind::CSV, "Only run specified scanners",
        [](Config& c, auto v) { c.enable_scanners = split_csv(v); }},
    {"--output", ArgKind::String, "Write JSON to FILE",
        [](Config& c, auto v) { c.output_file = std::string(v); }},
    // ...
}};

bool parse(int argc, char** argv, Config& cfg) {
    for(int i = 1; i < argc; ++i) {
        auto* spec = find_spec(argv[i]);
        if(spec && spec->handler) {
            spec->handler(cfg, get_value(spec->kind, i, argc, argv));
        }
    }
}
```

### Benefits

- **Single source of truth**: flag, type, help text, and behavior in one place
- **Uniform with scanner registry**: consistent pattern across codebase
- **Memory safe**: `std::array`, `std::string_view`, no allocations in hot path
- **Maintainable**: add new argument = add 1 line to table
- **Self-documenting**: help text generation automatic from table
- **Zero overhead**: compiles to same machine code as current if-else chain

### Implementation Plan

1. Update `ArgumentParser.h` with new `ArgSpec` structure
2. Define static `arg_specs_` table with all 71 arguments
3. Simplify `parse()` to iterate table and call handlers
4. Auto-generate `print_help()` from table
5. Run full test suite (`test_argument_parser*.cpp`)
6. Verify binary size unchanged (`size sys-scan`)

### Testing Strategy

- All existing tests must pass without modification
- Verify help output matches current format
- Check edge cases: unknown args, missing values, integer parsing
- Benchmark parse time (should be identical)

### References

- Scanner registry pattern: `src/scanners/ScannerRegistry.*`
- Current implementation: `src/core/ArgumentParser.cpp:78-420`
- Test coverage: `tests/test_argument_parser*.cpp` (919 tests)

### Notes

- **Not a breaking change**: External API/behavior unchanged
- **Security**: No new dependencies, pure C++20
- **Compatibility**: Works with existing `Config` structure
- **Future**: Could enable runtime argument registration for plugins
