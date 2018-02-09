project(pki)

# Required cmake version
cmake_minimum_required(VERSION 2.6.0)

# global needed variables
set(APPLICATION_NAME ${PROJECT_NAME})

# Un-comment the following line to add 'javac' options (e. g. - "-g" debugging)
#set(CMAKE_JAVA_COMPILE_FLAGS "-g")

if (NOT DEFINED VERSION)
    set(VERSION "10.0.0")
endif(NOT DEFINED VERSION)

string(REGEX REPLACE "^([0-9]+).*" "\\1" APPLICATION_VERSION_MAJOR ${VERSION})
string(REGEX REPLACE "^[0-9]+\\.([0-9]+).*" "\\1" APPLICATION_VERSION_MINOR ${VERSION})
string(REGEX REPLACE "^[0-9]+\\.[0-9]+\\.([0-9]+).*" "\\1" APPLICATION_VERSION_PATCH ${VERSION})

set(APP_SERVER "tomcat8" CACHE STRING "Application server")

option(WITH_SERVER "Build server package" ON)
option(WITH_JAVADOC "Build Javadoc package" ON)
option(WITH_TEST "Run unit tests" ON)
option(WITH_PYTHON2 "Build with Python 2 support" ON)
option(WITH_PYTHON3 "Build with Python 3 support" ON)
option(WITH_PYTHON3_SERVER "Build server with Python 3" OFF)

if (BUILD_DOGTAG_PKI_THEME)
    set(APPLICATION_FLAVOR_DOGTAG_PKI_THEME TRUE)
elseif (BUILD_REDHAT_PKI_THEME)
    set(APPLICATION_FLAVOR_REDHAT_PKI_THEME TRUE)
elseif (BUILD_PKI_CORE)
    set(APPLICATION_FLAVOR_PKI_CORE TRUE)
elseif (BUILD_PKI_CONSOLE)
    set(APPLICATION_FLAVOR_PKI_CONSOLE TRUE)
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

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/dist)

# required for all PKI components
include(JUnit)

# search for libraries

# required for all PKI components EXCEPT Theme-based components
if (NOT APPLICATION_FLAVOR_DOGTAG_PKI_THEME   AND
    NOT APPLICATION_FLAVOR_REDHAT_PKI_THEME)
    find_package(NSPR REQUIRED)
    find_package(NSS REQUIRED)
endif ()

# ONLY required for Java-based PKI components
if (APPLICATION_FLAVOR_PKI_CORE         OR
    APPLICATION_FLAVOR_PKI_CONSOLE      OR
    APPLICATION_FLAVOR_DOGTAG_PKI_THEME OR
    APPLICATION_FLAVOR_REDHAT_PKI_THEME)
    find_package(Java REQUIRED)
    find_package(JNI REQUIRED)
endif ()

# ONLY required for PKI_CORE
if (APPLICATION_FLAVOR_PKI_CORE)
    find_package(Ldap REQUIRED)
    # required for native 'tpsclient' utility
    find_package(APR REQUIRED)
endif ()

# Find out if we have threading available
set(CMAKE_THREAD_PREFER_PTHREADS ON)
find_package(Threads)

# Python 2 / 3 detection
function(find_site_packages pythonexecutable targetname)
    execute_process(
        COMMAND
            ${pythonexecutable} -c
            "from distutils.sysconfig import get_python_lib; print(get_python_lib())"
        OUTPUT_VARIABLE
            out
        ERROR_VARIABLE
            error
        RESULT_VARIABLE
            result
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(result)
        message(FATAL_ERROR "${pythonexecutable} not found: ${result} / ${error}")
    else()
        message(STATUS "${targetname} ${out}")
        set(${targetname} ${out})
        set(${targetname} ${out} PARENT_SCOPE)
    endif()
endfunction(find_site_packages)

# Find default Python
# When WITH_PYTHON3_SERVER is enabled, then require Python 3, otherwise 2.
if (WITH_PYTHON3_SERVER)
    if (NOT WITH_PYTHON3)
        message(FATAL_ERROR "WITH_PYTHON3_SERVER=ON requires WITH_PYTHON3=ON")
    endif(NOT WITH_PYTHON3)
    # find Python interpreter
    set(Python_ADDITIONAL_VERSIONS 3)
    find_package(PythonInterp REQUIRED)
    # FindPythonInterp doesn't restrict version with ADDITIONAL_VERSIONS
    if (PYTHON_VERSION_STRING VERSION_LESS "3.5.0")
        message(FATAL_ERROR "Detect Python interpreter < 3.5.0")
    endif()
else()
    if (NOT WITH_PYTHON2)
        message(FATAL_ERROR "WITH_PYTHON3_SERVER=OFF requires WITH_PYTHON2=ON")
    endif(NOT WITH_PYTHON2)
    # find Python interpreter
    set(Python_ADDITIONAL_VERSIONS 2)
    find_package(PythonInterp REQUIRED)
    # only accept python2.7 as python2
    if (PYTHON_VERSION_STRING VERSION_LESS "2.7.0" OR PYTHON_VERSION_STRING VERSION_GREATER "3.0")
        message(FATAL_ERROR "Detect Python interpreter != 2.7")
    endif()
endif()
message(STATUS "Building pki.server for ${PYTHON_VERSION_STRING}")

# Find site-packages for Python 2 and 3
if (WITH_PYTHON2)
    find_site_packages("python2" PYTHON2_SITE_PACKAGES)
    message(STATUS "Building Python 2 pki client package")
else()
    message(STATUS "Skipping Python 2 pki client package")
endif(WITH_PYTHON2)

if (WITH_PYTHON3)
    find_site_packages("python3" PYTHON3_SITE_PACKAGES)
    message(STATUS "Building Python 3 pki client package")
else()
    message(STATUS "Skipping Python 3 pki client package")
endif(WITH_PYTHON3)

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
    APPLICATION_FLAVOR_PKI_CONSOLE)
    add_subdirectory(base)
endif ()

# 'Themes' MUST be "mutually-exclusive"!
if (APPLICATION_FLAVOR_DOGTAG_PKI_THEME)
    add_subdirectory(dogtag)
elseif (APPLICATION_FLAVOR_REDHAT_PKI_THEME)
    add_subdirectory(redhat)
endif ()
