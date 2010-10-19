#=============================================================================
# Copyright 2002-2009 Kitware, Inc.
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

function(ADD_JNI_HEADERS _CLASSPATH _CLASSNAMES _HEADERS _DEPENDS)
    add_custom_command(
        OUTPUT
            ${_HEADERS}
        COMMAND ${JAVA_HEADER}
            -classpath ${_CLASSPATH}
            -jni
            -d ${CMAKE_CURRENT_BINARY_DIR}
            ${_CLASSNAMES}
        DEPENDS
            ${_DEPENDS}
    )
endfunction(ADD_JNI_HEADERS)
