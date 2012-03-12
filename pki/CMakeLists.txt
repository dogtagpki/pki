project(pki)

# Required cmake version
cmake_minimum_required(VERSION 2.6.0)

# global needed variables
set(APPLICATION_NAME ${PROJECT_NAME})

set(APPLICATION_VERSION_MAJOR "9")
set(APPLICATION_VERSION_MINOR "0")
set(APPLICATION_VERSION_PATCH "0")

if (BUILD_IPA_PKI_THEME)
    set(APPLICATION_FLAVOR_IPA_PKI_THEME TRUE)
    # override APPLICATION VERSION
    set(APPLICATION_VERSION_PATCH "5")
elseif (BUILD_DOGTAG_PKI_THEME)
    set(APPLICATION_FLAVOR_DOGTAG_PKI_THEME TRUE)
    # override APPLICATION VERSION
    set(APPLICATION_VERSION_PATCH "11")
elseif (BUILD_REDHAT_PKI_THEME)
    set(APPLICATION_FLAVOR_REDHAT_PKI_THEME TRUE)
elseif (BUILD_PKI_CORE)
    set(APPLICATION_FLAVOR_PKI_CORE TRUE)
    # override APPLICATION VERSION
    set(APPLICATION_VERSION_PATCH "18")
elseif (BUILD_PKI_KRA)
    set(APPLICATION_FLAVOR_PKI_KRA TRUE)
    # override APPLICATION VERSION
    set(APPLICATION_VERSION_PATCH "10")
elseif (BUILD_PKI_OCSP)
    set(APPLICATION_FLAVOR_PKI_OCSP TRUE)
    set(APPLICATION_VERSION_PATCH "9")
elseif (BUILD_PKI_RA)
    set(APPLICATION_FLAVOR_PKI_RA TRUE)
    set(APPLICATION_VERSION_PATCH "4")
elseif (BUILD_PKI_TKS)
    set(APPLICATION_FLAVOR_PKI_TKS TRUE)
    set(APPLICATION_VERSION_PATCH "9")
elseif (BUILD_PKI_TPS)
    set(APPLICATION_FLAVOR_PKI_TPS TRUE)
    # override APPLICATION VERSION
    set(APPLICATION_VERSION_PATCH "7")
elseif (BUILD_PKI_CONSOLE)
    set(APPLICATION_FLAVOR_PKI_CONSOLE TRUE)
    # override APPLICATION VERSION
    set(APPLICATION_VERSION_PATCH "5")
elseif (BUILD_PKI_MIGRATE)
    set(APPLICATION_FLAVOR_PKI_MIGRATE TRUE)
    # override APPLICATION VERSION
    set(APPLICATION_VERSION_PATCH "2")
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
include(UseJava)

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
    APPLICATION_FLAVOR_PKI_KRA       OR
    APPLICATION_FLAVOR_PKI_OCSP      OR
    APPLICATION_FLAVOR_PKI_TKS       OR
    APPLICATION_FLAVOR_PKI_CONSOLE   OR
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


# check subdirectories
if (APPLICATION_FLAVOR_PKI_CORE      OR
    APPLICATION_FLAVOR_PKI_KRA       OR
    APPLICATION_FLAVOR_PKI_OCSP      OR
    APPLICATION_FLAVOR_PKI_RA        OR
    APPLICATION_FLAVOR_PKI_TKS       OR
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

