#===============================================================================
# SE05X driver: root CMake
#===============================================================================
# One file, two build systems:
#
# - ESP-IDF (ESP_PLATFORM): this folder is an ESP-IDF component. Point
#   EXTRA_COMPONENT_DIRS at it, check it out under components/, or add it as a
#   component-manager git dependency. menuconfig reads _config/Kconfig.
# - Any other CMake build (host, STM32, RP2040, nRF, ...): one INTERFACE target,
#   se05x, consumed as se05x::se05x both through add_subdirectory() and
#   through find_package(se05x) after install.
#
#   cmake -S . -B build -DSE05X_BUILD_TESTS=ON
#   cmake --build build && ctest --test-dir build --output-on-failure
#===============================================================================
cmake_minimum_required(VERSION 3.16)

include(${CMAKE_CURRENT_LIST_DIR}/cmake/se05x_build_settings.cmake)

#===============================================================================
# ESP-IDF component
#===============================================================================
if(ESP_PLATFORM)
    idf_component_register(
        SRCS ${SE05X_SOURCE_FILES}
        INCLUDE_DIRS ${SE05X_PUBLIC_INCLUDE_DIRS}
        REQUIRES ${SE05X_IDF_REQUIRES}
        KCONFIG ${CMAKE_CURRENT_LIST_DIR}/_config/Kconfig
    )
    if(SE05X_SOURCE_FILES)
        target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_20)
    else()
        target_compile_features(${COMPONENT_LIB} INTERFACE cxx_std_20)
        # menuconfig's "irreversible operations" switch reaches the headers as the build flag.
        if(CONFIG_SE05X_ENABLE_IRREVERSIBLE)
            target_compile_definitions(${COMPONENT_LIB} INTERFACE SE05X_ENABLE_IRREVERSIBLE=1)
        endif()
    endif()
    return()
endif()

project(se05x_driver
    VERSION ${SE05X_VERSION}
    DESCRIPTION "C++20 driver and hardware root-of-trust facade for the NXP EdgeLock SE050, SE051 and SE052 secure elements over I2C (T=1, GlobalPlatform SCP03, IoT applet), with the transport, crypto and timing behind ports."
    LANGUAGES CXX)

include(GNUInstallDirs)

# ISO C++20 for every target this project builds (tests, fuzzers, examples), never the GNU dialect
# that CMake picks by default (handbook KB-CPP-001, KB-CPP20-001). CXX_EXTENSIONS does not travel
# through an INTERFACE target, so each folder that builds a target sets it as well.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# The installed layout keeps the source tree's inc/ + src/ pair, because each header includes
# its "../src/*.ipp" relative to itself:
#   <prefix>/include/se05x/inc/*.hpp, se05x_version.h
#   <prefix>/include/se05x/src/*.ipp
set(SE05X_INSTALL_INCLUDEDIR "${CMAKE_INSTALL_INCLUDEDIR}/se05x/inc")

#===============================================================================
# Target
#===============================================================================
add_library(${SE05X_TARGET_NAME} INTERFACE)
target_include_directories(${SE05X_TARGET_NAME}
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/inc>
        $<BUILD_INTERFACE:${SE05X_VERSION_HEADER_DIR}>
        $<INSTALL_INTERFACE:${SE05X_INSTALL_INCLUDEDIR}>
)
target_compile_features(${SE05X_TARGET_NAME} INTERFACE cxx_std_20)

# se05x::se05x everywhere: the alias for add_subdirectory(), EXPORT_NAME for the installed package.
add_library(se05x::se05x ALIAS ${SE05X_TARGET_NAME})
set_target_properties(${SE05X_TARGET_NAME} PROPERTIES EXPORT_NAME se05x)

# Irreversible operations (lifecycle locks, key lock, transport lock) are compiled out unless this is
# ON (owner assumption, docs/safety.md). The default is OFF and it must stay OFF in release builds
# that have not been rehearsed on a spare chip.
option(SE05X_ENABLE_IRREVERSIBLE "Compile the irreversible operations (default OFF)" OFF)
if(SE05X_ENABLE_IRREVERSIBLE)
    target_compile_definitions(${SE05X_TARGET_NAME} INTERFACE SE05X_ENABLE_IRREVERSIBLE=1)
endif()

option(SE05X_ENABLE_WARNINGS "Add -Wall -Wextra -Wpedantic to every target that links se05x::se05x" OFF)
if(SE05X_ENABLE_WARNINGS)
    target_compile_options(${SE05X_TARGET_NAME} INTERFACE -Wall -Wextra -Wpedantic)
endif()

#===============================================================================
# Host tests, documentation snippets, install check (tests/)
#===============================================================================
option(SE05X_BUILD_TESTS "Build the host tests in tests/" OFF)
option(SE05X_BUILD_FUZZERS "Also build the libFuzzer targets in tests/fuzz/ (Clang only)" OFF)
if(SE05X_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

#===============================================================================
# Install and package export
#===============================================================================
include(CMakePackageConfigHelpers)

install(TARGETS ${SE05X_TARGET_NAME} EXPORT se05xTargets
    INCLUDES DESTINATION ${SE05X_INSTALL_INCLUDEDIR})

install(DIRECTORY inc/ DESTINATION ${SE05X_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp" PATTERN "*.h")
install(FILES "${SE05X_VERSION_HEADER}" DESTINATION ${SE05X_INSTALL_INCLUDEDIR})
install(DIRECTORY src/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/se05x/src
    FILES_MATCHING PATTERN "*.ipp")

install(EXPORT se05xTargets
    FILE se05xTargets.cmake
    NAMESPACE se05x::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/se05x)

configure_package_config_file(
    "${CMAKE_CURRENT_LIST_DIR}/cmake/se05xConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/se05xConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/se05x)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/se05xConfigVersion.cmake"
    VERSION ${SE05X_VERSION}
    COMPATIBILITY SameMajorVersion
    ARCH_INDEPENDENT)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/se05xConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/se05xConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/se05x)
