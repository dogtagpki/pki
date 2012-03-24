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

# This should be included before the _INIT variables are
# used to initialize the cache.  Since the rule variables
# have if blocks on them, users can still define them here.
# But, it should still be after the platform file so changes can
# be made to those values.

set(CMAKE_Java_OUTPUT_EXTENSION .class)

if (CMAKE_USER_MAKE_RULES_OVERRIDE)
    include(${CMAKE_USER_MAKE_RULES_OVERRIDE})
endif (CMAKE_USER_MAKE_RULES_OVERRIDE)

if (CMAKE_USER_MAKE_RULES_OVERRIDE_Java)
   include(${CMAKE_USER_MAKE_RULES_OVERRIDE_Java})
endif (CMAKE_USER_MAKE_RULES_OVERRIDE_Java)

# this is a place holder if java needed flags for javac they would go here.
if (NOT CMAKE_Java_CREATE_STATIC_LIBRARY)
#    if (WIN32)
#        set(class_files_mask "*.class")
#    else(WIN32)
         set(class_files_mask ".")
#    endif(WIN32)

    set(CMAKE_Java_CREATE_STATIC_LIBRARY
        "<CMAKE_Java_ARCHIVE> -cf <TARGET> -C <OBJECT_DIR> ${class_files_mask}")
    # "${class_files_mask}" should really be "<OBJECTS>" but compling a *.java
    # file can create more than one *.class file...
endif (NOT CMAKE_Java_CREATE_STATIC_LIBRARY)

if (NOT CMAKE_Java_CREATE_SHARED_LIBRARY)
    set(CMAKE_Java_CREATE_SHARED_LIBRARY ${CMAKE_Java_CREATE_STATIC_LIBRARY})
endif (NOT CMAKE_Java_CREATE_SHARED_LIBRARY)

# compile a Java file into an object file
if (NOT CMAKE_Java_COMPILE_OBJECT)
    set(CMAKE_Java_COMPILE_OBJECT
        "<CMAKE_Java_COMPILER> <FLAGS> <SOURCE> -d <OBJECT_DIR>")
endif (NOT CMAKE_Java_COMPILE_OBJECT)

if (NOT ${CMAKE_Java_LINK_EXECUTABLE})
#    if (WIN32)
#        set(class_files_mask "*.class")
#    else(WIN32)
         set(class_files_mask ".")
#    endif(WIN32)

    set(CMAKE_Java_LINK_EXECUTABLE
        "<CMAKE_Java_ARCHIVE> -cf <TARGET> -C <OBJECT_DIR> ${class_files_mask}")
    # "${class_files_mask}" should really be "<OBJECTS>" but compling a *.java
    # file can create more than one *.class file...
endif (NOT ${CMAKE_Java_LINK_EXECUTABLE})

# set java include flag option and the separator for multiple include paths
set(CMAKE_INCLUDE_FLAG_Java "-classpath ")
if (WIN32 AND NOT CYGWIN)
    set(CMAKE_INCLUDE_FLAG_SEP_Java ";")
else (WIN32 AND NOT CYGWIN)
    set(CMAKE_INCLUDE_FLAG_SEP_Java ":")
endif(WIN32 AND NOT CYGWIN)
