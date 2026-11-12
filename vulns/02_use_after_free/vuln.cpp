// CWE-416: Use After Free
// The session object is freed and then read again through the dangling
// pointer. Without a sanitizer this usually does NOT crash: the allocator
// has simply reused the first bytes of the chunk for its own bookkeeping,
// so the program prints corrupted data and carries on.
#include <cstdio>
#include <cstdlib>
#include <cstring>

struct Session {
    char user[16];
    int privilege;
};

int main(int argc, char** argv) {
    const char* name = (argc > 1) ? argv[1] : "guest";

    Session* s = static_cast<Session*>(malloc(sizeof(Session)));
    if (!s) return 1;
    std::strncpy(s->user, name, sizeof(s->user) - 1);
    s->user[sizeof(s->user) - 1] = '\0';
    s->privilege = 0;
    std::printf("before free: user=%s privilege=%d\n", s->user, s->privilege);

    free(s);

    // BUG: s is dangling here
    std::printf("after  free: user=%s privilege=%d\n", s->user, s->privilege);
    return 0;
}
