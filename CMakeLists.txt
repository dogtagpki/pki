project(pki)

# Required cmake version
cmake_minimum_required(VERSION 3.0.0)

# global needed variables
set(APPLICATION_NAME ${PROJECT_NAME})

# Skip recompiling when already compiled
set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY TRUE)

# Suppress install messages
set(CMAKE_INSTALL_MESSAGE NEVER)

# Un-comment the following line to add 'javac' options (e. g. - "-g" debugging)
set(CMAKE_JAVA_COMPILE_FLAGS "-Xlint:deprecation")

if (NOT DEFINED VERSION)
    set(VERSION "10.0.0")
endif(NOT DEFINED VERSION)

if (NOT DEFINED NSS_DEFAULT_DB_TYPE)
    set(NSS_DEFAULT_DB_TYPE "dbm")
endif(NOT DEFINED NSS_DEFAULT_DB_TYPE)

if (NOT DEFINED P11_KIT_TRUST)
    set(P11_KIT_TRUST "/usr/lib64/pkcs11/p11-kit-trust.so")
endif(NOT DEFINED P11_KIT_TRUST)

if (NOT DEFINED THEME)
    set(VERSION "dogtag")
endif(NOT DEFINED THEME)

string(REGEX REPLACE "^([0-9]+).*" "\\1" APPLICATION_VERSION_MAJOR ${VERSION})
string(REGEX REPLACE "^[0-9]+\\.([0-9]+).*" "\\1" APPLICATION_VERSION_MINOR ${VERSION})
string(REGEX REPLACE "^[0-9]+\\.[0-9]+\\.([0-9]+).*" "\\1" APPLICATION_VERSION_PATCH ${VERSION})

set(APP_SERVER "tomcat-8.0" CACHE STRING "Application server")

option(WITH_SERVER "Build server package" ON)
option(WITH_JAVADOC "Build Javadoc package" ON)
option(WITH_TEST "Run unit tests" ON)

set(APPLICATION_VERSION "${APPLICATION_VERSION_MAJOR}.${APPLICATION_VERSION_MINOR}.${APPLICATION_VERSION_PATCH}")

if(WITH_TEST)
    enable_testing()
endif(WITH_TEST)

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

# required for all PKI components EXCEPT Theme-based components
if (BUILD_PKI_CORE OR BUILD_PKI_CONSOLE)
    find_package(NSPR REQUIRED)
    find_package(NSS REQUIRED)
endif ()

find_package(Java REQUIRED)
find_package(JNI REQUIRED)

# For convenience, update helpful variables if unset.
if (NOT JRE_HOME)
    if (EXISTS "${JAVA_HOME}/jre")
        set(JRE_HOME "${JAVA_HOME}/jre")
    else ()
        set(JRE_HOME "${JAVA_HOME}")
    endif ()
endif ()
if (NOT PKI_JAVA_PATH)
    if (EXISTS "${JRE_HOME}/bin/java")
        set(PKI_JAVA_PATH "${JRE_HOME}/bin/java")
    endif ()
endif ()

# ONLY required for PKI_CORE
if (BUILD_PKI_CORE)
    find_package(Ldap REQUIRED)
    # required for native 'tpsclient' utility
    find_package(APR REQUIRED)
endif ()

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
if (BUILD_PKI_CORE OR BUILD_PKI_CONSOLE)
    include(DefinePythonSitePackages)
endif ()

# config.h checks
include(ConfigureChecks)
configure_file(cmake/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

add_definitions(-DHAVE_CONFIG_H)

# handle custom PKI Java path
if (PKI_JAVA_PATH STREQUAL "")
    set(PKI_JAVA_PATH "${Java_JAVA_EXECUTABLE}")
endif ()

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

# check subdirectories
if (BUILD_PKI_CORE OR BUILD_PKI_CONSOLE)
    add_subdirectory(base)
endif ()

if (NOT "${THEME}" STREQUAL "")
    add_subdirectory(themes)
endif ()

add_subdirectory(tests)

install(
    FILES
        pom.xml
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}
)

install(
    FILES
        tools/pylintrc
        tox.ini
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/tests
)

install(
    FILES
        tools/pki-lint
    DESTINATION
        ${SHARE_INSTALL_PREFIX}/${APPLICATION_NAME}/tests/bin
    PERMISSIONS
        OWNER_EXECUTE OWNER_WRITE OWNER_READ
        GROUP_EXECUTE GROUP_READ
        WORLD_EXECUTE WORLD_READ
)
