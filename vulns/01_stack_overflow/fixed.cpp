// Fix for CWE-121: validate length first, then use std::string, which owns
// its storage and cannot be overrun by a copy.
#include <cstdio>
#include <string>
#include <string_view>

static constexpr std::size_t kMaxName = 15;

static bool greet(std::string_view input) {
    if (input.size() > kMaxName) {   // reject instead of silently truncating
        std::fprintf(stderr, "error: name too long (max %zu)\n", kMaxName);
        return false;
    }
    const std::string name{input};
    std::printf("Hello, %s\n", name.c_str());
    return true;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <name>\n", argv[0]);
        return 2;
    }
    if (!greet(argv[1])) return 1;
    std::puts("returned normally");
    return 0;
}
