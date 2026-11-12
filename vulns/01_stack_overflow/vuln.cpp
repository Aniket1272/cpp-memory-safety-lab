// CWE-121: Stack-based Buffer Overflow
// An attacker-controlled string is copied into a fixed 16-byte stack buffer
// with no length check. Inputs >= 16 bytes overwrite adjacent stack memory
// (saved frame pointer, then the return address).
#include <cstdio>
#include <cstring>

static void greet(const char* input) {
    char buf[16];
    strcpy(buf, input);
    std::printf("Hello, %s\n", buf);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <name>\n", argv[0]);
        return 2;
    }
    greet(argv[1]);
    std::puts("returned normally");
    return 0;
}
