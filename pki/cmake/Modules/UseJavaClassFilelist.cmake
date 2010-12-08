#
# This script create a list of compiled Java class files to be added to a
# jar file. This avoids including cmake files which get created in the
# binary directory.
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

if (CMAKE_JAVA_CLASS_OUTPUT_PATH)
    if (EXISTS "${CMAKE_JAVA_CLASS_OUTPUT_PATH}")

        # if it exists, obtain the length of the selected jar classes prefix
        if (CMAKE_JAR_CLASSES_PREFIX)
            string(LENGTH "${CMAKE_JAR_CLASSES_PREFIX}"
                   _JAR_CLASSES_PREFIX_LENGTH)
        endif (CMAKE_JAR_CLASSES_PREFIX)

        # glob for class files
        file(GLOB_RECURSE _JAVA_GLOBBED_FILES "${CMAKE_JAVA_CLASS_OUTPUT_PATH}/*.class")

        # create relative path
        set(_JAVA_CLASS_FILES)
        foreach(_JAVA_GLOBBED_FILE ${_JAVA_GLOBBED_FILES})
            file(RELATIVE_PATH _JAVA_CLASS_FILE ${CMAKE_JAVA_CLASS_OUTPUT_PATH} ${_JAVA_GLOBBED_FILE})
            if (CMAKE_JAR_CLASSES_PREFIX)
                # extract the prefix from this java class file corresponding
                # to the length of the selected jar classes prefix
                string(SUBSTRING "${_JAVA_CLASS_FILE}"
                       0 ${_JAR_CLASSES_PREFIX_LENGTH} _JAVA_CLASS_PREFIX)
                # save this java class file ONLY if its prefix is the
                # same as the selected java classes prefix
                if (_JAVA_CLASS_PREFIX STREQUAL CMAKE_JAR_CLASSES_PREFIX)
                    set(_JAVA_CLASS_FILES
                        "${_JAVA_CLASS_FILES}${_JAVA_CLASS_FILE}\n")
                endif (_JAVA_CLASS_PREFIX STREQUAL CMAKE_JAR_CLASSES_PREFIX)
            else ()
                # save ALL java class files
                set(_JAVA_CLASS_FILES
                    "${_JAVA_CLASS_FILES}${_JAVA_CLASS_FILE}\n")
            endif (CMAKE_JAR_CLASSES_PREFIX)
        endforeach(_JAVA_GLOBBED_FILE ${_JAVA_GLOBBED_FILES})

        # write to file
        file(WRITE ${CMAKE_JAVA_CLASS_OUTPUT_PATH}/java_class_filelist ${_JAVA_CLASS_FILES})

    else (EXISTS "${CMAKE_JAVA_CLASS_OUTPUT_PATH}")
        message(SEND_ERROR "FATAL: Java class output path doesn't exist")
    endif (EXISTS "${CMAKE_JAVA_CLASS_OUTPUT_PATH}")
else (CMAKE_JAVA_CLASS_OUTPUT_PATH)
    message(SEND_ERROR "FATAL: Can't find CMAKE_JAVA_CLASS_OUTPUT_PATH")
endif (CMAKE_JAVA_CLASS_OUTPUT_PATH)
