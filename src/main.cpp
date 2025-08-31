#include "core/ScannerRegistry.h"
#include "core/ScanContext.h"  // Added ScanContext include
#include "core/Report.h"
#include "core/JSONWriter.h"
#include "core/Logging.h"
#include "core/RuleEngine.h"
#include "core/Config.h"
#include "core/ArgumentParser.h"
#include "core/ConfigValidator.h"
#include "core/OutputWriter.h"
#include "core/GPGSigner.h"
#include "core/RuleEngineInitializer.h"
#include "core/ExitCodeHandler.h"
#include "core/Privilege.h"
#include "BuildInfo.h" // configured header (CMake adds generated dir to include path)
#include <iostream>
#include <filesystem>

using namespace sys_scan;

int main(int argc, char** argv) {
    Logger::instance().set_level(LogLevel::Info);

    // Parse command line arguments
    ArgumentParser arg_parser;
    Config cfg;

    // Handle special cases first
    if (argc >= 2) {
        std::string first_arg = argv[1];
        if (first_arg == "--help") {
            arg_parser.print_help();
            return 0;
        }
        if (first_arg == "--version") {
            arg_parser.print_version();
            return 0;
        }
    }

    // Parse arguments
    if (!arg_parser.parse(argc, argv, cfg)) {
        return 2; // Parse error
    }

    // No need to set global config - using ScanContext pattern instead

    // Validate configuration
    ConfigValidator config_validator;
    if (!config_validator.validate(cfg)) {
        return 2; // Validation error
    }

    // Apply fast-scan optimizations
    config_validator.apply_fast_scan_optimizations(cfg);

    // Load external files
    if (!config_validator.load_external_files(cfg)) {
        return 2; // File loading error
    }

    // Initialize rule engine if enabled
    RuleEngineInitializer rule_initializer;
    if (!rule_initializer.initialize(cfg)) {
        return cfg.rules_allow_legacy ? 3 : 2; // Legacy rules error or general error
    }

    // Register scanners
    ScannerRegistry registry;
    registry.register_all_default(cfg);

    // Drop privileges if requested
    if (cfg.drop_priv) {
        Logger::instance().info("Privilege drop requested - initializing resources before dropping capabilities");
        drop_capabilities(cfg.keep_cap_dac);
        Logger::instance().info("Capabilities dropped, proceeding with restricted privileges");
    }

    // Apply seccomp profile
    if (cfg.seccomp) {
        Logger::instance().info("Seccomp profile requested - applying syscall restrictions");
        if (!apply_seccomp_profile()) {
            Logger::instance().error("Failed to apply seccomp profile");
            if (cfg.seccomp_strict) {
                Logger::instance().error("Seccomp strict mode enabled, exiting");
                return 4;
            } else {
                Logger::instance().warn("Seccomp failed but continuing in non-strict mode");
            }
        } else {
            Logger::instance().info("Seccomp profile applied successfully");
        }
    }

    // Run scanners
    Report report;
    ScanContext context(cfg, report);  // Create ScanContext with config and report references
    registry.run_all(context);

    // Write output
    OutputWriter output_writer;
    if (!output_writer.write_report(report, cfg)) {
        return 2; // Output error
    }

    // Write environment file if requested
    if (!output_writer.write_env_file(cfg)) {
        return 2; // Env file error
    }

    // Sign output if requested
    GPGSigner gpg_signer;
    if (!gpg_signer.sign_file(cfg)) {
        return 2; // Signing error
    }

    // Calculate and return exit code
    ExitCodeHandler exit_handler;
    return exit_handler.calculate_exit_code(report, cfg);
}
