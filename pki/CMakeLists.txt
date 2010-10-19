project(pki)

# Required cmake version
cmake_minimum_required(VERSION 2.6.0)

# global needed variables
set(APPLICATION_NAME ${PROJECT_NAME})
if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/dogtag")
    set(APPLICATION_FLAVOUR_DOGTAG TRUE)
endif (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/dogtag")
if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/rhcs")
    set(APPLICATION_FLAVOUR_RHCS TRUE)
endif (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/rhcs")

set(APPLICATION_VERSION_MAJOR "1")
set(APPLICATION_VERSION_MINOR "3")
set(APPLICATION_VERSION_PATCH "0")

set(APPLICATION_VERSION "${APPLICATION_VERSION_MAJOR}.${APPLICATION_VERSION_MINOR}.${APPLICATION_VERSION_PATCH}")

# where to look first for cmake modules, before ${CMAKE_ROOT}/Modules/ is checked
set(CMAKE_MODULE_PATH
  ${CMAKE_SOURCE_DIR}/cmake/Modules
)

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
find_package(Java REQUIRED)
find_package(JNI REQUIRED)
find_package(NSPR REQUIRED)
find_package(NSS REQUIRED)
find_package(MozLDAP REQUIRED)
find_package(APR REQUIRED)

# Find out if we have threading available
set(CMAKE_THREAD_PREFER_PTHREADS ON)
find_package(Threads)

# config.h checks
include(ConfigureChecks.cmake)
configure_file(config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

add_definitions(-DHAVE_CONFIG_H)

# uninstall target
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)


# check subdirectories
add_subdirectory(base)
if (APPLICATION_FLAVOUR_DOGTAG)
    add_subdirectory(dogtag)
endif (APPLICATION_FLAVOUR_DOGTAG)
