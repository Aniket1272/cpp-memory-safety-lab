// Fix for CWE-415: a std::unique_ptr<char[]> frees the buffer exactly once,
// whichever path leaves the function. The error path can now simply return.
#include <cstdio>
#include <cstring>
#include <memory>

int main(int argc, char** argv) {
    auto buf = std::make_unique<char[]>(32);
    std::snprintf(buf.get(), 32, "working buffer");

    if (argc > 1 && std::strcmp(argv[1], "fail") == 0) {
        std::fprintf(stderr, "error path taken\n");
        return 1;                    // buf released automatically
    }

    std::puts("done");
    return 0;
}
