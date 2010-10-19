project(osutil_java Java)

set(OSUTIL_JAVA_OBJECT_DIR "${CMAKE_CURRENT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/osutil.dir/" PARENT_SCOPE)
set(OSUTIL_JAR "${CMAKE_CURRENT_BINARY_DIR}/osutil.jar" CACHE INTERNAL "osutil jar file")

set(osutil_java_SRCS
    com/netscape/osutil/LibC.java
    com/netscape/osutil/NTEventLogger.java
    com/netscape/osutil/OSUtil.java
    com/netscape/osutil/ResourceLimit.java
    com/netscape/osutil/Signal.java
    com/netscape/osutil/SignalListener.java
    com/netscape/osutil/UserID.java
)

add_jar(osutil ${osutil_java_SRCS})

install(
    FILES
        ${OSUTIL_JAR}
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)
