#include "pattern_declarations.h"

// smart pointers (unique_ptr) to make garbage collection automatic.
// Can't construct a static vector because unique_ptr's have no copy constructors for some reason.
extern std::vector<std::unique_ptr<CallInstPattern>> CallInstPatterns;
extern std::vector<std::unique_ptr<ICmpInstPattern>> ICmpInstPatterns;
extern std::vector<std::unique_ptr<Pattern>> MiscInstPatterns;