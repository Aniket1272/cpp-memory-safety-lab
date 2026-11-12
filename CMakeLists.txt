cmake_minimum_required(VERSION 3.16)
project(cpp_memory_safety_lab LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Flags are set per target on purpose, so each build variant is explicit.
#
#  vuln        : optimizations off, debug info on, distro hardening turned off
#                (Ubuntu/Debian GCC enables stack protector, PIE and FORTIFY by
#                default, which would hide the bugs we want to study).
#  vuln_asan   : same as vuln + AddressSanitizer + UndefinedBehaviorSanitizer.
#  fixed       : the corrected program, normal optimized build, warnings on,
#                default distro hardening left untouched.
#  fixed_asan  : the corrected program under the sanitizers (must run clean).

set(VULN_FLAGS   -O0 -g -fno-stack-protector -fno-omit-frame-pointer
                 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fno-pie)
set(SAN_FLAGS    -fsanitize=address,undefined -fno-omit-frame-pointer)
set(WARN_FLAGS   -Wall -Wextra -Wpedantic)

function(add_case id dir)
  set(src ${CMAKE_SOURCE_DIR}/vulns/${dir})

  add_executable(${id}_vuln ${src}/vuln.cpp)
  target_compile_options(${id}_vuln PRIVATE ${VULN_FLAGS})
  target_link_options(${id}_vuln PRIVATE -no-pie)

  add_executable(${id}_vuln_asan ${src}/vuln.cpp)
  target_compile_options(${id}_vuln_asan PRIVATE ${VULN_FLAGS} ${SAN_FLAGS})
  target_link_options(${id}_vuln_asan PRIVATE -no-pie -fsanitize=address,undefined)

  add_executable(${id}_fixed ${src}/fixed.cpp)
  target_compile_options(${id}_fixed PRIVATE -O2 -g ${WARN_FLAGS})

  add_executable(${id}_fixed_asan ${src}/fixed.cpp)
  target_compile_options(${id}_fixed_asan PRIVATE -O1 -g ${WARN_FLAGS} ${SAN_FLAGS})
  target_link_options(${id}_fixed_asan PRIVATE -fsanitize=address,undefined)
endfunction()

add_case(case01 01_stack_overflow)
add_case(case02 02_use_after_free)
add_case(case03 03_double_free)
add_case(case04 04_integer_overflow)

# `cmake --build build --target analysis` builds everything, then runs the
# static analyzers + sanitizer runs and writes analysis/results/.
add_custom_target(analysis
  COMMAND python3 ${CMAKE_SOURCE_DIR}/analysis/run_analysis.py --build-dir ${CMAKE_BINARY_DIR}
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  DEPENDS case01_vuln case01_vuln_asan case01_fixed case01_fixed_asan
          case02_vuln case02_vuln_asan case02_fixed case02_fixed_asan
          case03_vuln case03_vuln_asan case03_fixed case03_fixed_asan
          case04_vuln case04_vuln_asan case04_fixed case04_fixed_asan
  USES_TERMINAL)
