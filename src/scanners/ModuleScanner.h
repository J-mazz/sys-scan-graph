#pragma once
#include "../core/Scanner.h"
namespace sys_scan { class ModuleScanner : public Scanner { public: std::string name() const override { return "modules"; } std::string description() const override { return "List loaded kernel modules"; } void scan(Report& report) override; }; }
