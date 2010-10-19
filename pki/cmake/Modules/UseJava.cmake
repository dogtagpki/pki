#
# This file provides functions for Java support.
#
# Available Functions:
#
#   add_jar(TARGET_NAME SRC1 SRC2 .. SRCN RCS1 RCS2 .. RCSN)
#
#   This command create a <TARGET_NAME>.jar. It compiles the given source
#   files (SRC) and adds the given resource files (RCS) to the jar file.
#   If only resource files are given then just a jar file is created.
#
#   Additional instructions:
#       To add compile flags to the target you can set these flags with
#       the following variable:
#
#           set(CMAKE_JAVA_COMPILE_FLAGS -nowarn)
#
#       To add a path or a jar file to the class path you can do this
#       with the CMAKE_JAVA_INCLUDE_PATH variable.
#
#           set(CMAKE_JAVA_INCLUDE_PATH /usr/share/java/shibboleet.jar)
#
#=============================================================================
# Copyright 2010      Andreas schneider <asn@redhat.com>
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

function(JAVA_COPY_FILE _SRC _DST)
    # Removes all path containing .svn or CVS or CMakeLists.txt during the copy
    if (NOT ${_SRC} MATCHES ".*\\.svn|CVS|CMakeLists\\.txt.*")

        if (CMAKE_VERBOSE_MAKEFILE)
            message(STATUS "Copy file from ${_SRC} to ${_DST}")
        endif (CMAKE_VERBOSE_MAKEFILE)

        # Creates directory if necessary
        get_filename_component(_PATH ${_DST} PATH)
        file(MAKE_DIRECTORY ${_PATH})

        execute_process(
            COMMAND
                ${CMAKE_COMMAND} -E copy_if_different ${_SRC} ${_DST}
            OUTPUT_QUIET
        )
    endif (NOT ${_SRC} MATCHES ".*\\.svn|CVS|CMakeLists\\.txt.*")
endfunction(JAVA_COPY_FILE)

function(ADD_JAR _TARGET_NAME)
    set(_JAVA_SOURCE_FILES ${ARGN})

    if (LIBRARY_OUTPUT_PATH)
        set(CMAKE_JAVA_LIBRARY_OUTPUT_PATH ${LIBRARY_OUTPUT_PATH})
    else (LIBRARY_OUTPUT_PATH)
        set(CMAKE_JAVA_LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR})
    endif (LIBRARY_OUTPUT_PATH)

    set(CMAKE_JAVA_INCLUDE_PATH
        ${CMAKE_JAVA_INCLUDE_PATH}
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_JAVA_OBJECT_OUTPUT_PATH}
        ${CMAKE_JAVA_LIBRARY_OUTPUT_PATH}
    )

    if (WIN32 AND NOT CYGWIN)
        set(CMAKE_JAVA_INCLUDE_FLAG_SEP ";")
    else (WIN32 AND NOT CYGWIN)
        set(CMAKE_JAVA_INCLUDE_FLAG_SEP ":")
    endif(WIN32 AND NOT CYGWIN)

    foreach (JAVA_INCLUDE_DIR ${CMAKE_JAVA_INCLUDE_PATH})
       set(CMAKE_JAVA_INCLUDE_PATH_FINAL "${CMAKE_JAVA_INCLUDE_PATH_FINAL}${CMAKE_JAVA_INCLUDE_FLAG_SEP}${JAVA_INCLUDE_DIR}")
    endforeach(JAVA_INCLUDE_DIR)

    set(CMAKE_JAVA_CLASS_OUTPUT_PATH "${CMAKE_CURRENT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/${_TARGET_NAME}.dir")

    add_custom_target(${_TARGET_NAME} ALL)

    get_target_property(_JAVA_OUTPUT_NAME ${_TARGET_NAME} OUTPUT_NAME)
    if (NOT _JAVA_OUTPUT_NAME)
        set(_JAVA_OUTPUT_NAME "${_TARGET_NAME}.jar")
    endif (NOT _JAVA_OUTPUT_NAME)

    set(_JAVA_CLASS_FILES)
    set(_JAVA_COMPILE_FILES)
    set(_JAVA_RESOURCE_FILES)
    foreach(_JAVA_SOURCE_FILE ${_JAVA_SOURCE_FILES})
        get_filename_component(_JAVA_EXT ${_JAVA_SOURCE_FILE} EXT)
        get_filename_component(_JAVA_FILE ${_JAVA_SOURCE_FILE} NAME_WE)
        get_filename_component(_JAVA_PATH ${_JAVA_SOURCE_FILE} PATH)

        if (_JAVA_EXT MATCHES ".java")
            list(APPEND _JAVA_COMPILE_FILES ${_JAVA_SOURCE_FILE})
            set(_JAVA_CLASS_FILE "${_JAVA_PATH}/${_JAVA_FILE}.class")
            set(_JAVA_CLASS_FILES ${_JAVA_CLASS_FILES} ${_JAVA_CLASS_FILE})

        else (_JAVA_EXT MATCHES ".java")
            java_copy_file(${CMAKE_CURRENT_SOURCE_DIR}/${_JAVA_SOURCE_FILE}
                           ${CMAKE_JAVA_CLASS_OUTPUT_PATH}/${_JAVA_SOURCE_FILE})
            list(APPEND _JAVA_RESOURCE_FILES ${_JAVA_SOURCE_FILE})
        endif (_JAVA_EXT MATCHES ".java")
    endforeach(_JAVA_SOURCE_FILE)

    # create an empty java_class_filelist
    file(WRITE ${CMAKE_JAVA_CLASS_OUTPUT_PATH}/java_class_filelist "")

    if (_JAVA_COMPILE_FILES)
        # Compile the java files and create a list of class files
        add_custom_command(
            TARGET ${_TARGET_NAME}
            COMMAND ${CMAKE_Java_COMPILER}
                ${CMAKE_JAVA_COMPILE_FLAGS}
                -classpath ${CMAKE_JAVA_INCLUDE_PATH_FINAL}
                -d ${CMAKE_JAVA_CLASS_OUTPUT_PATH}
                ${_JAVA_COMPILE_FILES}
            COMMAND ${CMAKE_COMMAND}
                -DCMAKE_JAVA_CLASS_OUTPUT_PATH=${CMAKE_JAVA_CLASS_OUTPUT_PATH}
                -P ${CMAKE_MODULE_PATH}/JavaClassFilelist.cmake
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            COMMENT "Building Java objects for ${_TARGET_NAME}.jar"
        )
    endif (_JAVA_COMPILE_FILES)

    # create the jar file
    add_custom_command(
        TARGET ${_TARGET_NAME}
        COMMAND ${CMAKE_Java_ARCHIVE}
            -cf ${CMAKE_CURRENT_BINARY_DIR}/${_JAVA_OUTPUT_NAME}
            ${_JAVA_RESOURCE_FILES} @java_class_filelist
        WORKING_DIRECTORY ${CMAKE_JAVA_CLASS_OUTPUT_PATH}
        COMMENT "Creating Java archive ${_JAVA_OUTPUT_NAME}"
    )
endfunction(ADD_JAR)
