// CWE-415: Double Free
// A classic error-handling bug: the error branch cleans up but forgets to
// return, so execution falls through to the normal cleanup and frees the
// same buffer a second time. Trigger it with the argument "fail".
#include <cstdio>
#include <cstdlib>
#include <cstring>

static void cleanup(char* p) {
    free(p);
}

int main(int argc, char** argv) {
    char* buf = static_cast<char*>(malloc(32));
    if (!buf) return 1;
    std::snprintf(buf, 32, "working buffer");

    if (argc > 1 && std::strcmp(argv[1], "fail") == 0) {
        std::fprintf(stderr, "error path taken\n");
        cleanup(buf);
        // BUG: missing 'return 1;' -- falls through to cleanup below
    }

    cleanup(buf);                    // second free when "fail" was given
    std::puts("done");
    return 0;
}
