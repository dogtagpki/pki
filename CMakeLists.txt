# Required cmake version
cmake_minimum_required(VERSION 3.26)

project(pki)

# global needed variables
set(APPLICATION_NAME ${PROJECT_NAME})

# Skip recompiling when already compiled
set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY TRUE)

if (NOT DEFINED CMAKE_INSTALL_MESSAGE)
    set(CMAKE_INSTALL_MESSAGE LAZY)
endif (NOT DEFINED CMAKE_INSTALL_MESSAGE)

if (NOT DEFINED PRODUCT_NAME)
    set(PRODUCT_NAME "Dogtag PKI")
endif(NOT DEFINED PRODUCT_NAME)

set(IMPL_VERSION "${VERSION}-${RELEASE}")

if (NOT DEFINED NSS_DEFAULT_DB_TYPE)
    set(NSS_DEFAULT_DB_TYPE "sql")
endif(NOT DEFINED NSS_DEFAULT_DB_TYPE)

if (NOT DEFINED P11_KIT_TRUST)
    set(P11_KIT_TRUST "/usr/lib64/pkcs11/p11-kit-trust.so")
endif(NOT DEFINED P11_KIT_TRUST)

if (NOT DEFINED PYTHON_EXECUTABLE)
    set(PYTHON_EXECUTABLE "/usr/bin/python3")
endif(NOT DEFINED PYTHON_EXECUTABLE)

if (NOT DEFINED THEME)
    set(THEME "dogtag")
endif(NOT DEFINED THEME)

string(REGEX REPLACE "^([0-9]+).*" "\\1" APPLICATION_VERSION_MAJOR ${VERSION})
string(REGEX REPLACE "^[0-9]+\\.([0-9]+).*" "\\1" APPLICATION_VERSION_MINOR ${VERSION})
string(REGEX REPLACE "^[0-9]+\\.[0-9]+\\.([0-9]+).*" "\\1" APPLICATION_VERSION_PATCH ${VERSION})

set(APP_SERVER "tomcat-10.1" CACHE STRING "Application server")

option(WITH_JAVA "Build Java binaries." TRUE)

option(WITH_SERVER "Build server package" ON)
option(WITH_CA "Build CA package" ON)
option(WITH_KRA "Build KRA package" ON)
option(WITH_OCSP "Build OCSP package" ON)
option(WITH_TKS "Build TKS package" ON)
option(WITH_TPS "Build TPS package" ON)
option(WITH_ACME "Build ACME package" ON)
option(WITH_EST "Build EST package" ON)
option(WITH_JAVADOC "Build Javadoc package" ON)
option(WITH_THEME "Build theme package" ON)
option(WITH_META "Build meta package" ON)
option(WITH_TESTS "Build tests package" ON)
option(RUN_TESTS "Run unit tests" ON)

set(APPLICATION_VERSION "${APPLICATION_VERSION_MAJOR}.${APPLICATION_VERSION_MINOR}.${APPLICATION_VERSION_PATCH}")

if(RUN_TESTS)
    enable_testing()
endif(RUN_TESTS)

# where to look first for cmake modules
# (before ${CMAKE_ROOT}/Modules/ is checked)
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/Modules)

# add definitions
include(DefineCMakeDefaults)
include(DefinePlatformDefaults)
include(DefineCompilerFlags)
include(DefineInstallationPaths)
include(DefineOptions)
include(CPackConfig)

# disallow in-source build
include(MacroEnsureOutOfSourceBuild)
macro_ensure_out_of_source_build("${PROJECT_NAME} requires an out of source build. Please create a separate build directory and run 'cmake /path/to/${PROJECT_NAME} [options]' there.")

# add macros
include(MacroCopyFile)
include(Java)

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/dist)

# required for all PKI components
include(JUnit)

# search for libraries

find_package(NSPR REQUIRED)
find_package(NSS REQUIRED)

find_package(Java REQUIRED)
find_package(JNI REQUIRED)

find_package(Ldap REQUIRED)
# required for native 'tpsclient' utility
find_package(APR REQUIRED)

# Find out if we have threading available
set(CMAKE_THREAD_PREFER_PTHREADS ON)
find_package(Threads)

# NSS default database type
if (NSS_DEFAULT_DB_TYPE STREQUAL "dbm")
    message(STATUS "Using old 'dbm' format for NSS_DEFAULT_DB_TYPE")
elseif (NSS_DEFAULT_DB_TYPE STREQUAL "sql")
    message(STATUS "Using new 'sql' format for NSS_DEFAULT_DB_TYPE")
else()
    message(FATAL_ERROR "Unsupported NSS_DEFAULT_DB_TYPE=${NSS_DEFAULT_DB_TYPE}")
endif()

# Detect default Python interpreter
# Set PYTHON3_SITE_PACKAGES
include(DefinePythonSitePackages)

# config.h checks
include(ConfigureChecks)
configure_file(cmake/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

add_definitions(-DHAVE_CONFIG_H)

# java target
add_custom_target(
    java
    COMMENT "Building Java binaries"
)

# theme target
add_custom_target(
    theme
    COMMENT "Building PKI theme"
)

# javadoc target
add_custom_target(
    javadoc
    COMMENT "Building Javadoc"
)

# native target
add_custom_target(
    native ALL
    COMMENT "Building native binaries"
)

# uninstall target
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
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

add_subdirectory(base)

if(WITH_THEME)
    add_subdirectory(themes)
endif(WITH_THEME)

if(WITH_TESTS)
    add_subdirectory(tests)
endif(WITH_TESTS)

install(
    FILES
        pom.xml
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}
)
