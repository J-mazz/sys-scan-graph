#pragma once
#include "../core/Scanner.h"
#include <memory>
namespace sys_scan { std::unique_ptr<Scanner> make_ebpf_scanner(); }
