// CWE-190 -> CWE-122: Integer Overflow leading to Heap Buffer Overflow
// The allocation size is computed in 32-bit unsigned arithmetic. For a large
// record count the multiplication wraps around to a tiny value, malloc
// succeeds with a tiny buffer, and the copy loop then writes far past it.
// Try: ./04_vuln 4            (benign)
//      ./04_vuln 268435457    (0x10000001 * 16 wraps to 16 bytes)
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <record-count>\n", argv[0]);
        return 2;
    }
    const std::uint32_t count = static_cast<std::uint32_t>(std::strtoul(argv[1], nullptr, 10));
    const std::uint32_t record_size = 16;

    const std::uint32_t total = count * record_size;   // BUG: can wrap (well-defined, but wrong)
    std::fprintf(stderr, "count=%u total=%u\n", count, total);

    auto* buf = static_cast<unsigned char*>(std::malloc(total));
    if (!buf) return 1;

    for (std::uint32_t i = 0; i < count; ++i) {
        std::memset(buf + static_cast<std::size_t>(i) * record_size, 'A', record_size);
    }

    std::puts("done");
    std::free(buf);
    return 0;
}