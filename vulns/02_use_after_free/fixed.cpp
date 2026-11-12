// Fix for CWE-416: the Session is owned by a unique_ptr, so its lifetime is
// tied to the scope. All uses happen while it is alive; destruction is
// automatic and cannot be forgotten or done twice.
#include <cstdio>
#include <cstring>
#include <memory>

struct Session {
    char user[16];
    int privilege;
};

int main(int argc, char** argv) {
    const char* name = (argc > 1) ? argv[1] : "guest";

    {
        auto s = std::make_unique<Session>();
        std::strncpy(s->user, name, sizeof(s->user) - 1);
        s->user[sizeof(s->user) - 1] = '\0';
        s->privilege = 0;
        std::printf("in scope: user=%s privilege=%d\n", s->user, s->privilege);
    }   // Session destroyed here; no pointer to it remains in scope

    std::puts("session closed");
    return 0;
}
