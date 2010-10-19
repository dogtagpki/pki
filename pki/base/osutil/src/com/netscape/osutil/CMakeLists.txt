project(osutil_c C)

set(osutil_c_HDRS
    LIBC.h
    ResourceLimit.h
    Signal.h
    UserID.h
    OSUtil.h
)

set(osutil_c_SRCS
    LibC.c
    OSUtil.c
    ResourceLimit.c
    Signal.c
    UserID.c
)

include_directories(${JNI_INCLUDE_DIRS} ${NSPR_INCLUDE_DIRS} ${NSS_INCLUDE_DIRS})

add_custom_command(
    OUTPUT
        ${osutil_c_HDRS}
    COMMAND
        ${JAVA_HEADER}
            -classpath ${OSUTIL_JAVA_OBJECT_DIR}
            -jni -d ${CMAKE_CURRENT_BINARY_DIR}
            com.netscape.osutil.LibC
            com.netscape.osutil.ResourceLimit
            com.netscape.osutil.Signal
            com.netscape.osutil.UserID
            com.netscape.osutil.OSUtil
    DEPENDS
        osutil_java
)

add_library(osutil SHARED ${osutil_c_HDRS} ${osutil_c_SRCS})
