project(osutil_java Java)

set(osutil_java_SRCS
    com/netscape/osutil/LibC.java
    com/netscape/osutil/NTEventLogger.java
    com/netscape/osutil/OSUtil.java
    com/netscape/osutil/ResourceLimit.java
    com/netscape/osutil/Signal.java
    com/netscape/osutil/SignalListener.java
    com/netscape/osutil/UserID.java
)

set(CMAKE_JNI_TARGET TRUE)
set(CMAKE_JAVA_TARGET_VERSION ${OSUTIL_LIBRARY_VERSION})
add_jar(osutil ${osutil_java_SRCS})
install_jar(osutil ${LIB_INSTALL_DIR}/osutil)
install_jni_symlink(osutil ${JAVA_LIB_INSTALL_DIR})

set(OSUTIL_JAVA_OBJECT_DIR ${osutil_CLASS_DIR} PARENT_SCOPE)
set(OSUTIL_JAR ${osutil_JAR_FILE} CACHE INTERNAL "osutil jar file")
