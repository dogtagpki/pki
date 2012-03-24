#=============================================================================
# Copyright 2004-2009 Kitware, Inc.
#
# Distributed under the OSI-approved BSD License (the "License");
# see accompanying file Copyright.txt for details.
#
# This software is distributed WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the License for more information.
#=============================================================================
# (To distributed this file outside of CMake, substitute the full
#  License text for the above reference.)

# This file is used by EnableLanguage in cmGlobalGenerator to
# determine that that selected Java compiler can actually compile
# and link the most basic of programs.   If not, a fatal error
# is set and cmake stops processing commands and will not generate
# any makefiles or projects.

set(CMAKE_Java_COMPILER_WORKS 1 CACHE INTERNAL "")

if (NOT CMAKE_Java_COMPILER_WORKS)
    message(STATUS "Check for working Java compiler: ${CMAKE_Java_COMPILER}")

    file(WRITE ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/testJavaCompiler.java
        "class HelloWorldApp {\n"
        "  public static void main(String[] args) {\n"
        "    System.out.println("Hello World!");\n"
        "  }\n"
        "}\n"
    )

    try_compile(CMAKE_Java_COMPILER_WORKS
        ${CMAKE_BINARY_DIR}
        ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/testJavaCompiler.java
        OUTPUT_VARIABLE OUTPUT
    )

    if (CMAKE_Java_COMPILER_WORKS)
        message(STATUS "Check for working Java compiler: ${CMAKE_C_COMPILER} -- works")
        file(APPEND ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeOutput.log
            "Determining if the C compiler works passed with "
            "the following output:\n${OUTPUT}\n\n"
        )
        set(CMAKE_Java_COMPILER_WORKS 1 CACHE INTERNAL "")
    endif (CMAKE_Java_COMPILER_WORKS)
endif (NOT CMAKE_Java_COMPILER_WORKS)
