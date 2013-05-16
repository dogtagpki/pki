project(pki)

# Required cmake version
cmake_minimum_required(VERSION 2.6.0)

# global needed variables
set(APPLICATION_NAME ${PROJECT_NAME})

if (NOT DEFINED VERSION)
    set(VERSION "10.0.0")
endif(NOT DEFINED VERSION)

string(REGEX REPLACE "^([0-9]+).*" "\\1" APPLICATION_VERSION_MAJOR ${VERSION})
string(REGEX REPLACE "^[0-9]+\\.([0-9]+).*" "\\1" APPLICATION_VERSION_MINOR ${VERSION})
string(REGEX REPLACE "^[0-9]+\\.[0-9]+\\.([0-9]+).*" "\\1" APPLICATION_VERSION_PATCH ${VERSION})

option(WITH_JAVADOC "Build with Javadoc" ON)
option(BUILD_PKI_SELINUX "Build pki-selinux" OFF)

if (BUILD_IPA_PKI_THEME)
    set(APPLICATION_FLAVOR_IPA_PKI_THEME TRUE)
elseif (BUILD_DOGTAG_PKI_THEME)
    set(APPLICATION_FLAVOR_DOGTAG_PKI_THEME TRUE)
elseif (BUILD_REDHAT_PKI_THEME)
    set(APPLICATION_FLAVOR_REDHAT_PKI_THEME TRUE)
elseif (BUILD_PKI_CORE)
    set(APPLICATION_FLAVOR_PKI_CORE TRUE)
elseif (BUILD_PKI_RA)
    set(APPLICATION_FLAVOR_PKI_RA TRUE)
elseif (BUILD_PKI_TPS)
    set(APPLICATION_FLAVOR_PKI_TPS TRUE)
elseif (BUILD_PKI_CONSOLE)
    set(APPLICATION_FLAVOR_PKI_CONSOLE TRUE)
elseif (BUILD_PKI_MIGRATE)
    set(APPLICATION_FLAVOR_PKI_MIGRATE TRUE)
endif ()

set(APPLICATION_VERSION "${APPLICATION_VERSION_MAJOR}.${APPLICATION_VERSION_MINOR}.${APPLICATION_VERSION_PATCH}")

# where to look first for cmake modules
# (before ${CMAKE_ROOT}/Modules/ is checked)
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/Modules)

# add definitions
include(DefineCMakeDefaults)
include(DefinePlatformDefaults)
include(DefineCompilerFlags)
include(DefineInstallationPaths)
include(DefineOptions.cmake)
include(CPackConfig.cmake)

# disallow in-source build
include(MacroEnsureOutOfSourceBuild)
macro_ensure_out_of_source_build("${PROJECT_NAME} requires an out of source build. Please create a separate build directory and run 'cmake /path/to/${PROJECT_NAME} [options]' there.")

# add macros
include(MacroCopyFile)
include(Java)

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/classes)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/dist)

# required for all PKI components EXCEPT IPA_PKI_THEME, PKI_RA, and PKI_TPS
if (NOT APPLICATION_FLAVOR_IPA_PKI_THEME   AND
    NOT APPLICATION_FLAVOR_PKI_RA          AND
    NOT APPLICATION_FLAVOR_PKI_TPS)
    include(JUnit)

    add_custom_target(test)
endif ()

# search for libraries

# required for all PKI components EXCEPT Theme-based components and PKI_MIGRATE
if (NOT APPLICATION_FLAVOR_IPA_PKI_THEME      AND
    NOT APPLICATION_FLAVOR_DOGTAG_PKI_THEME   AND
    NOT APPLICATION_FLAVOR_REDHAT_PKI_THEME   AND
    NOT APPLICATION_FLAVOR_PKI_MIGRATE)
    find_package(NSPR REQUIRED)
    find_package(NSS REQUIRED)
endif ()

# ONLY required for Java-based PKI components
if (APPLICATION_FLAVOR_PKI_CORE      OR
    APPLICATION_FLAVOR_PKI_TPS       OR
    APPLICATION_FLAVOR_PKI_CONSOLE   OR
    APPLICATION_FLAVOR_DOGTAG_PKI_THEME OR
    APPLICATION_FLAVOR_PKI_MIGRATE)
    find_package(Java REQUIRED)
    find_package(JNI REQUIRED)
endif ()

# ONLY required for PKI_CORE or PKI_TPS
if (APPLICATION_FLAVOR_PKI_CORE   OR
    APPLICATION_FLAVOR_PKI_TPS)
    find_package(Ldap REQUIRED)
endif ()

# ONLY required for PKI_TPS
if (APPLICATION_FLAVOR_PKI_TPS)
    find_package(APR REQUIRED)
    find_package(Svrcore REQUIRED)
endif ()

# Find out if we have threading available
set(CMAKE_THREAD_PREFER_PTHREADS ON)
find_package(Threads)

find_package(PythonInterp REQUIRED)
execute_process(
    COMMAND
        ${PYTHON_EXECUTABLE} -c
        "from distutils.sysconfig import get_python_lib; print get_python_lib()"
    OUTPUT_VARIABLE
        PYTHON_SITE_PACKAGES
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# config.h checks
include(ConfigureChecks.cmake)
configure_file(config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

add_definitions(-DHAVE_CONFIG_H)

# uninstall target
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
               "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
               IMMEDIATE @ONLY)

add_custom_target(uninstall
                  COMMAND ${CMAKE_COMMAND}
                      -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)

# clean-dist target
add_custom_target(clean-dist
    COMMAND ${CMAKE_COMMAND}
        -E remove_directory ${CMAKE_BINARY_DIR}/dist
)

# clean-cmake target
add_custom_target(clean-cmake
    COMMAND ${CMAKE_COMMAND}
        -E remove_directory ${CMAKE_BINARY_DIR}/base
    COMMAND ${CMAKE_COMMAND}
        -E remove_directory ${CMAKE_BINARY_DIR}/CMakeFiles
    COMMAND ${CMAKE_COMMAND}
        -E remove -f
        ${CMAKE_BINARY_DIR}/CMakeCache.txt
        ${CMAKE_BINARY_DIR}/cmake_install.cmake
        ${CMAKE_BINARY_DIR}/cmake_uninstall.cmake
        ${CMAKE_BINARY_DIR}/config.h
        ${CMAKE_BINARY_DIR}/CPackConfig.cmake
        ${CMAKE_BINARY_DIR}/CPackSourceConfig.cmake
        ${CMAKE_BINARY_DIR}/install_manifest.txt
        ${CMAKE_BINARY_DIR}/Makefile
)

# check subdirectories
if (APPLICATION_FLAVOR_PKI_CORE      OR
    APPLICATION_FLAVOR_PKI_RA        OR
    APPLICATION_FLAVOR_PKI_TPS       OR
    APPLICATION_FLAVOR_PKI_CONSOLE   OR
    APPLICATION_FLAVOR_PKI_MIGRATE)
    add_subdirectory(base)
endif ()

# 'Themes' MUST be "mutually-exclusive"!
if (APPLICATION_FLAVOR_IPA_PKI_THEME)
    add_subdirectory(dogtag)
elseif (APPLICATION_FLAVOR_DOGTAG_PKI_THEME)
    add_subdirectory(dogtag)
elseif (APPLICATION_FLAVOR_REDHAT_PKI_THEME)
    add_subdirectory(redhat)
endif ()
