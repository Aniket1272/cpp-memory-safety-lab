// Fix for CWE-190/CWE-122: validate the untrusted count against both a policy
// limit and the arithmetic limit BEFORE multiplying, and let std::vector own
// the memory.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <vector>

static constexpr std::uint32_t kRecordSize = 16;
static constexpr std::uint32_t kMaxRecords = 1u << 20;   // policy limit

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <record-count>\n", argv[0]);
        return 2;
    }
    const std::uint64_t count = std::strtoull(argv[1], nullptr, 10);

    if (count > kMaxRecords ||
        count > std::numeric_limits<std::uint32_t>::max() / kRecordSize) {
        std::fprintf(stderr, "error: record count out of range\n");
        return 1;
    }

    std::vector<unsigned char> buf(static_cast<std::size_t>(count) * kRecordSize);
    for (std::size_t i = 0; i < count; ++i) {
        for (std::size_t j = 0; j < kRecordSize; ++j) buf[i * kRecordSize + j] = 'A';
    }
    std::printf("count=%llu bytes=%zu\n", static_cast<unsigned long long>(count), buf.size());
    std::puts("done");
    return 0;
}
