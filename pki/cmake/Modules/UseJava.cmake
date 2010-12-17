#
# This file provides functions for Java support.
#
# Available Functions:
#
#   add_jar(TARGET_NAME SRC1 SRC2 .. SRCN RCS1 RCS2 .. RCSN)
#
#   This command creates a <TARGET_NAME>.jar. It compiles the given source
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
#       To use a different output name for the target you can set it with:
#
#           set(CMAKE_JAVA_TARGET_OUTPUT_NAME shibboleet.jar)
#           add_jar(foobar foobar.java)
#
#       To add a VERSION to the target output name you can set it using
#       CMAKE_JAVA_TARGET_VERSION. This will create a jar file with the name
#       shibboleet-1.0.0.jar and will create a symlink shibboleet.jar pointing
#       to the jar with the version information.
#
#           set(CMAKE_JAVA_TARGET_VERSION 1.2.0)
#           add_jar(shibboleet shibbotleet.java)
#
#        If the target is a JNI library, utilize the following commands to
#        create a JNI symbolic link:
#
#           set(CMAKE_JNI_TARGET TRUE)
#           set(CMAKE_JAVA_TARGET_VERSION 1.2.0)
#           add_jar(shibboleet shibbotleet.java)
#           install_jar(shibboleet ${LIB_INSTALL_DIR}/shibboleet)
#           install_jni_symlink(shibboleet ${JAVA_LIB_INSTALL_DIR})
#
#        If a single target needs to produce more than one jar from its
#        java source code, to prevent the accumulation of duplicate class
#        files in subsequent jars, set/reset CMAKE_JAR_CLASSES_PREFIX prior
#        to calling the add_jar() function:
#
#           set(CMAKE_JAR_CLASSES_PREFIX com/redhat/foo)
#           add_jar(foo foo.java)
#
#           set(CMAKE_JAR_CLASSES_PREFIX com/redhat/bar)
#           add_jar(bar bar.java)
#
#
#   Variables set:
#       The add_jar() functions sets some variables which can be used in the
#       same scope where add_jar() is called.
#
#       <target>_INSTALL_FILES      The files which should be installed. This
#                                   is used by install_jar().
#       <target>_JNI_SYMLINK        The JNI symlink which should be installed.
#                                   This is used by install_jni_symlink().
#       <target>_JAR_FILE           The location of the jar file so that you
#                                   can include it.
#       <target>_CLASS_DIR          The directory where the class files can be
#                                   found. For example to use them with javah.
#
#
#    install_jar(TARGET_NAME DESTINATION)
#
#    This command installs the TARGET_NAME files to the given DESTINATION. It
#    should be called in the same scope as add_jar() or it will fail.
#
#
#    install_jni_symlink(TARGET_NAME DESTINATION)
#
#    This command installs the TARGET_NAME JNI symlinks to the given
#    DESTINATION. It should be called in the same scope as add_jar()
#    or it will fail.
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

function (__java_copy_file src dest comment)
    add_custom_command(
        OUTPUT  ${dest}
        COMMAND cmake -E copy_if_different
        ARGS    ${src}
                ${dest}
        DEPENDS ${src}
        COMMENT ${comment})
endfunction (__java_copy_file src dest comment)

function(add_jar _TARGET_NAME)
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

    set(_JAVA_TARGET_OUTPUT_NAME "${_TARGET_NAME}.jar")
    if (CMAKE_JAVA_TARGET_OUTPUT_NAME AND CMAKE_JAVA_TARGET_VERSION)
        set(_JAVA_TARGET_OUTPUT_NAME "${CMAKE_JAVA_TARGET_OUTPUT_NAME}-${CMAKE_JAVA_TARGET_VERSION}.jar")
        set(_JAVA_TARGET_OUTPUT_LINK "${CMAKE_JAVA_TARGET_OUTPUT_NAME}.jar")
    elseif (CMAKE_JAVA_TARGET_VERSION)
        set(_JAVA_TARGET_OUTPUT_NAME "${_TARGET_NAME}-${CMAKE_JAVA_TARGET_VERSION}.jar")
        set(_JAVA_TARGET_OUTPUT_LINK "${_TARGET_NAME}.jar")
    elseif (CMAKE_JAVA_TARGET_OUTPUT_NAME)
        set(_JAVA_TARGET_OUTPUT_NAME "${CMAKE_JAVA_TARGET_OUTPUT_NAME}.jar")
    endif (CMAKE_JAVA_TARGET_OUTPUT_NAME AND CMAKE_JAVA_TARGET_VERSION)
    # reset
    set(CMAKE_JAVA_TARGET_OUTPUT_NAME)

    set(_JAVA_CLASS_FILES)
    set(_JAVA_COMPILE_FILES)
    set(_JAVA_DEPENDS)
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
            __java_copy_file(${CMAKE_CURRENT_SOURCE_DIR}/${_JAVA_SOURCE_FILE}
                             ${CMAKE_JAVA_CLASS_OUTPUT_PATH}/${_JAVA_SOURCE_FILE}
                             "Copying ${_JAVA_SOURCE_FILE} to the build directory")
            list(APPEND _JAVA_RESOURCE_FILES ${_JAVA_SOURCE_FILE})
        endif (_JAVA_EXT MATCHES ".java")
    endforeach(_JAVA_SOURCE_FILE)

    # Check if we have a local UseJavaClassFilelist.cmake
    if (EXISTS ${CMAKE_MODULE_PATH}/UseJavaClassFilelist.cmake)
        set(_JAVA_CLASS_FILELIST_SCRIPT ${CMAKE_MODULE_PATH}/UseJavaClassFilelist.cmake)
    elseif (EXISTS ${CMAKE_ROOT}/Modules/UseJavaClassFilelist.cmake)
        set(_JAVA_CLASS_FILELIST_SCRIPT ${CMAKE_ROOT}/Modules/UseJavaClassFilelist.cmake)
    endif (EXISTS ${CMAKE_MODULE_PATH}/UseJavaClassFilelist.cmake)

    # create an empty java_class_filelist
    file(WRITE ${CMAKE_JAVA_CLASS_OUTPUT_PATH}/java_class_filelist "")

    # Check if we have a local UseJavaSymlinks.cmake
    if (EXISTS ${CMAKE_MODULE_PATH}/UseJavaSymlinks.cmake)
        set(_JAVA_SYMLINK_SCRIPT ${CMAKE_MODULE_PATH}/UseJavaSymlinks.cmake)
    elseif (EXISTS ${CMAKE_ROOT}/Modules/UseJavaSymlinks.cmake)
        set(_JAVA_SYMLINK_SCRIPT ${CMAKE_ROOT}/Modules/UseJavaSymlinks.cmake)
    endif (EXISTS ${CMAKE_MODULE_PATH}/UseJavaSymlinks.cmake)

    # Add the target and make sure we have the latest resource files.
    add_custom_target(${_TARGET_NAME} ALL DEPENDS ${_JAVA_RESOURCE_FILES})

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
                -DCMAKE_JAR_CLASSES_PREFIX="${CMAKE_JAR_CLASSES_PREFIX}"
                -P ${_JAVA_CLASS_FILELIST_SCRIPT}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            COMMENT "Building Java objects for ${_TARGET_NAME}.jar"
        )
    endif (_JAVA_COMPILE_FILES)

    # create the jar file
    if (CMAKE_JNI_TARGET)
        add_custom_command(
            TARGET ${_TARGET_NAME}
            COMMAND ${CMAKE_Java_ARCHIVE}
                -cf ${CMAKE_CURRENT_BINARY_DIR}/${_JAVA_TARGET_OUTPUT_NAME}
                ${_JAVA_RESOURCE_FILES} @java_class_filelist
            COMMAND ${CMAKE_COMMAND}
                -D_JAVA_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR}
                -D_JAVA_TARGET_OUTPUT_NAME=${_JAVA_TARGET_OUTPUT_NAME}
                -D_JAVA_TARGET_OUTPUT_LINK=${_JAVA_TARGET_OUTPUT_LINK}
                -P ${_JAVA_SYMLINK_SCRIPT}
            COMMAND ${CMAKE_COMMAND}
                -D_JAVA_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR}
                -D_JAVA_TARGET_OUTPUT_NAME=${CMAKE_CURRENT_BINARY_DIR}/${_JAVA_TARGET_OUTPUT_NAME}
                -D_JAVA_TARGET_OUTPUT_LINK=${_JAVA_TARGET_OUTPUT_LINK}
                -P ${_JAVA_SYMLINK_SCRIPT}
            WORKING_DIRECTORY ${CMAKE_JAVA_CLASS_OUTPUT_PATH}
            COMMENT "Creating Java archive ${_JAVA_TARGET_OUTPUT_NAME}"
        )
    else ()
        add_custom_command(
            TARGET ${_TARGET_NAME}
            COMMAND ${CMAKE_Java_ARCHIVE}
                -cf ${CMAKE_CURRENT_BINARY_DIR}/${_JAVA_TARGET_OUTPUT_NAME}
                ${_JAVA_RESOURCE_FILES} @java_class_filelist
            COMMAND ${CMAKE_COMMAND}
                -D_JAVA_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR}
                -D_JAVA_TARGET_OUTPUT_NAME=${_JAVA_TARGET_OUTPUT_NAME}
                -D_JAVA_TARGET_OUTPUT_LINK=${_JAVA_TARGET_OUTPUT_LINK}
                -P ${_JAVA_SYMLINK_SCRIPT}
            WORKING_DIRECTORY ${CMAKE_JAVA_CLASS_OUTPUT_PATH}
            COMMENT "Creating Java archive ${_JAVA_TARGET_OUTPUT_NAME}"
        )
    endif (CMAKE_JNI_TARGET)

    set(${_TARGET_NAME}_INSTALL_FILES
        ${CMAKE_CURRENT_BINARY_DIR}/${_JAVA_TARGET_OUTPUT_NAME}
        PARENT_SCOPE)
    if (_JAVA_TARGET_OUTPUT_LINK)
        set(${_TARGET_NAME}_INSTALL_FILES
            ${CMAKE_CURRENT_BINARY_DIR}/${_JAVA_TARGET_OUTPUT_NAME}
            ${CMAKE_CURRENT_BINARY_DIR}/${_JAVA_TARGET_OUTPUT_LINK}
            PARENT_SCOPE)
        if (CMAKE_JNI_TARGET)
            set(${_TARGET_NAME}_JNI_SYMLINK
                ${CMAKE_CURRENT_BINARY_DIR}/${_JAVA_TARGET_OUTPUT_LINK}
                PARENT_SCOPE)
        endif (CMAKE_JNI_TARGET)
    endif (_JAVA_TARGET_OUTPUT_LINK)
    set(${_TARGET_NAME}_JAR_FILE
        ${CMAKE_CURRENT_BINARY_DIR}/${_JAVA_TARGET_OUTPUT_NAME} PARENT_SCOPE)
    set(${_TARGET_NAME}_CLASS_DIR
        ${CMAKE_JAVA_CLASS_OUTPUT_PATH}
         PARENT_SCOPE)
endfunction(add_jar)

function(INSTALL_JAR _TARGET_NAME _DESTINATION)
    if (${_TARGET_NAME}_INSTALL_FILES)
        install(
            FILES
                ${${_TARGET_NAME}_INSTALL_FILES}
            DESTINATION
                ${_DESTINATION}
        )
    else (${_TARGET_NAME}_INSTALL_FILES)
        message(SEND_ERROR "The target ${_TARGET_NAME} is not known in this scope.")
    endif (${_TARGET_NAME}_INSTALL_FILES)
endfunction(INSTALL_JAR _TARGET_NAME _DESTINATION)

function(INSTALL_JNI_SYMLINK _TARGET_NAME _DESTINATION)
    if (${_TARGET_NAME}_JNI_SYMLINK)
        install(
            FILES
                ${${_TARGET_NAME}_JNI_SYMLINK}
            DESTINATION
                ${_DESTINATION}
        )
    else (${_TARGET_NAME}_JNI_SYMLINK)
        message(SEND_ERROR "The target ${_TARGET_NAME} is not known in this scope.")
    endif (${_TARGET_NAME}_JNI_SYMLINK)
endfunction(INSTALL_JNI_SYMLINK _TARGET_NAME _DESTINATION)

