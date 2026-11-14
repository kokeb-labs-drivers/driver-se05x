#===============================================================================
# SE05X driver: build settings
#===============================================================================
# Read by the root CMakeLists.txt in both of its modes (plain CMake and the
# ESP-IDF component): target name, version, include directories, sources and
# ESP-IDF requirements. This file is the single source
# of the version; tests/CMakeLists.txt checks every other copy against it.
#===============================================================================

include_guard(GLOBAL)

set(SE05X_TARGET_NAME "se05x")

#===============================================================================
# Version (single source of truth)
#===============================================================================
set(SE05X_VERSION_MAJOR 0)
set(SE05X_VERSION_MINOR 1)
set(SE05X_VERSION_PATCH 0)
set(SE05X_VERSION "${SE05X_VERSION_MAJOR}.${SE05X_VERSION_MINOR}.${SE05X_VERSION_PATCH}")

#===============================================================================
# Generated version header (build tree, never the source tree)
#===============================================================================
set(SE05X_VERSION_TEMPLATE "${CMAKE_CURRENT_LIST_DIR}/../inc/se05x_version.h.in")
set(SE05X_VERSION_HEADER_DIR "${CMAKE_CURRENT_BINARY_DIR}/se05x_generated")
set(SE05X_VERSION_HEADER "${SE05X_VERSION_HEADER_DIR}/se05x_version.h")

# The directory must exist before ESP-IDF's idf_component_register() checks the include paths.
file(MAKE_DIRECTORY "${SE05X_VERSION_HEADER_DIR}")
configure_file("${SE05X_VERSION_TEMPLATE}" "${SE05X_VERSION_HEADER}" @ONLY)

#===============================================================================
# Public include directories, sources, ESP-IDF requirements
#===============================================================================
set(SE05X_PUBLIC_INCLUDE_DIRS
    "${CMAKE_CURRENT_LIST_DIR}/../inc"
    "${SE05X_VERSION_HEADER_DIR}"
)

# Header-only: the implementations are src/*.ipp, each included by its inc/ header.
set(SE05X_SOURCE_FILES)

set(SE05X_IDF_REQUIRES)
