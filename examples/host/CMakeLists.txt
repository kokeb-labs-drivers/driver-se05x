# =============================================================================
# SE05X driver: host example (any PC, no hardware)
# =============================================================================
# The facade against the simulated SE05x of the host tests (tests/model/),
# then a bus with nothing on it (tests/null_ports.hpp).
#
#   cmake -S examples/host -B build-example
#   cmake --build build-example && ./build-example/se05x_host_example
#
# The host tests also build this folder and run the example (CTest
# se05x_host_example), so it always compiles against the current headers.
# =============================================================================
cmake_minimum_required(VERSION 3.16)

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  project(se05x_host_example LANGUAGES CXX)
  add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../.. se05x)
endif()

# ISO C++20, also when this folder is built on its own (handbook KB-CPP20-001).
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(se05x_host_example main.cpp)
target_link_libraries(se05x_host_example PRIVATE se05x::se05x)
target_include_directories(se05x_host_example PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}
  ${CMAKE_CURRENT_LIST_DIR}/../../tests)
target_compile_features(se05x_host_example PRIVATE cxx_std_20)
target_compile_options(se05x_host_example PRIVATE -fno-exceptions -fno-rtti -Wall -Wextra -Wpedantic
  -pedantic-errors)
