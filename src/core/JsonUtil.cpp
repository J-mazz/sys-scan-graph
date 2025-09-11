#include "JsonUtil.h"
#include <sstream>
#include <iomanip>
#include <ctime>
namespace sys_scan { namespace jsonutil {
std::string escape(const std::string& s){ std::string o; o.reserve(s.size()+8); for(char c: s){ switch(c){ case '"': o+="\\\""; break; case '\\': o+="\\\\"; break; case '\n': o+="\\n"; break; case '\r': o+="\\r"; break; case '\t': o+="\\t"; break; default: if((unsigned char)c < 0x20 && c != '\t'){ std::ostringstream tmp; tmp<<"\\u"<<std::hex<<std::setw(4)<<std::setfill('0')<<(int)(unsigned char)c; o+=tmp.str(); } else o+=c; } } return o; }
std::string time_to_iso(std::chrono::system_clock::time_point tp){ if(!tp.time_since_epoch().count()) return ""; auto t = std::chrono::system_clock::to_time_t(tp); std::tm tm_buf{}; gmtime_r(&t,&tm_buf); char buf[32]; std::strftime(buf,sizeof(buf),"%Y-%m-%dT%H:%M:%SZ", &tm_buf); return buf; }
} }
