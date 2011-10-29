project(symkey Java)

find_file(JSS_JAR
    NAMES
        jss4.jar
    PATHS
    ${JAVA_LIB_INSTALL_DIR}
    /usr/share/java
)

set(symkey_java_SRCS
    com/netscape/symkey/SessionKey.java
)

set(CMAKE_JNI_TARGET TRUE)
set(CMAKE_JAVA_INCLUDE_PATH ${JSS_JAR})
set(CMAKE_JAVA_TARGET_VERSION ${APPLICATION_VERSION})

add_jar(symkey ${symkey_java_SRCS})
install_jar(symkey ${LIB_INSTALL_DIR}/symkey)
install_jni_symlink(symkey ${JAVA_LIB_INSTALL_DIR})

set(SYMKEY_JAVA_OBJECT_DIR ${symkey_CLASS_DIR} PARENT_SCOPE)
set(SYMKEY_JAR ${symkey_JAR_FILE} CACHE INTERNAL "symkey jar file")
