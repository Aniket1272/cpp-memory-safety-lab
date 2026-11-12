# Detection matrix

- Platform: Linux-6.18.58.1-microsoft-standard-WSL2-x86_64-with-glibc2.43
- g++: g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0
- cppcheck: Cppcheck 2.19.0
- clang-tidy: Ubuntu LLVM version 21.1.8

| Case | CWE | Cppcheck | clang-tidy | Plain run (no sanitizer) | ASan | UBSan | Fixed version |
|---|---|---|---|---|---|---|---|
| Stack buffer overflow | CWE-121 | Missed | Detected (+1 unrelated) | SIGSEGV | stack-buffer-overflow | Missed | Clean |
| Use after free | CWE-416 | Missed | Detected | exit 0, no crash | heap-use-after-free | Missed | Clean |
| Double free | CWE-415 | Missed | Detected (+2 unrelated) | SIGABRT (glibc: double free detected) | attempting double-free | Missed | Clean |
| Integer overflow -> heap overflow | CWE-190/122 | Missed | Missed (+2 unrelated) | SIGSEGV | heap-buffer-overflow | Missed | Clean |
