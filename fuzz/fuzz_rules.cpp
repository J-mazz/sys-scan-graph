#include "core/RuleEngine.h"
#include <cstdint>
#include <cstddef>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size){
    if(size>4096) return 0; // bound cost
    // TODO: expose a load_string API; currently this is a stub to exercise infrastructure.
    // For now just scan for pattern tokens.
    for(size_t i=0;i+4<size;i++){ if(data[i]=='r' && data[i+1]=='u' && data[i+2]=='l' && data[i+3]=='e') { /* touch path */ } }
    return 0;
}
