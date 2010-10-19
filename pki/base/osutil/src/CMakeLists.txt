project(osutil_java Java)

# this is ugly!
set(OSUTIL_JAVA_OBJECT_DIR "${CMAKE_CURRENT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/${PROJECT_NAME}.dir/com/netscape/osutil/")

set(osutil_java_SRCS
    com/netscape/osutil/LibC.java
    com/netscape/osutil/NTEventLogger.java
    com/netscape/osutil/OSUtil.java
    com/netscape/osutil/ResourceLimit.java
    com/netscape/osutil/Signal.java
    com/netscape/osutil/SignalListener.java
    com/netscape/osutil/UserID.java
)

add_library(osutil_java ${osutil_java_SRCS})

set_target_properties(osutil_java
    PROPERTIES
        OUTPUT_NAME
            osuitl
)

add_subdirectory(com/netscape/osutil)
