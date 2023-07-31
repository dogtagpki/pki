project(pki-javadoc)

# It is important to identify the version of 'javadoc' being utilized since
# different versions support different options.
#
# While 'cmake' contains numerous built-in references to the 'java' version,
# it contains no built-in references to either the 'javac' or 'javadoc'
# versions, and unfortunately, the specified version of 'java' may be
# different from the specified versions of 'javac' and 'javadoc'.
#
# Additionally, although 'javadoc' contains no command-line option to identify
# its version, it is important to note that 'javadoc' is supplied by the same
# package that supplies 'javac', and although multiple versions of these
# executables could co-exist on the same system, it is relatively safe to
# assert that the currently specified 'javac' and 'javadoc' will be the same
# version.
#
# As an example in support of this assertion, on systems which utilize
# '/usr/sbin/alternatives', setting the 'javac' version will also
# automatically set the 'javadoc' version to match the 'javac' version, and
# 'usr/sbin/alternatives' cannot be used to set a specific 'javadoc' version.
#
# Therefore, regardless of the 'java' version, this 'CMakeLists.txt' file will
# programmatically utilize the invoked 'javac' version information (output is
# to stderr) in order to correctly identify the supported 'javadoc' options:
#
#     # javac -version 2>&1 | awk -F \. '{printf $2}'
#
# NOTE:  Used 'cut' instead of 'awk' due to 'cmake' parsing limitations:
#
#     # javac -version 2>&1 | cut -f2 -d.
#
message( STATUS "Java_VERSION_STRING = '${Java_VERSION_STRING}'" )
execute_process(
    COMMAND
        javac -version
    ERROR_VARIABLE
        Javac_VERSION_OUTPUT
    OUTPUT_VARIABLE
        Javac_VERSION_OUTPUT
    ERROR_STRIP_TRAILING_WHITESPACE
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
message( STATUS "Javac_VERSION_OUTPUT = '${Javac_VERSION_OUTPUT}'" )
string(REGEX REPLACE ".* ([0-9]+).*" "\\1" Javadoc_VERSION_MAJOR ${Javac_VERSION_OUTPUT})
message( STATUS "Javadoc_VERSION_MAJOR = '${Javadoc_VERSION_MAJOR}'" )
string(REGEX REPLACE ".* [0-9]+\\.([0-9]+).*" "\\1" Javadoc_VERSION_MINOR ${Javac_VERSION_OUTPUT})
message( STATUS "Javadoc_VERSION_MINOR = '${Javadoc_VERSION_MINOR}'" )

# REMINDER:  Eventually, it would almost certainly be safer to obtain the
#            'Javadoc_VERSION_MAJOR' number as well and perform the check
#            on "'Javadoc_VERSION_MAJOR'.'Javadoc_VERSION_MINOR'".
#
set(doclintstr "")
if(((${Javadoc_VERSION_MAJOR} EQUAL 1) AND (${Javadoc_VERSION_MINOR} EQUAL 8)) OR (${Javadoc_VERSION_MAJOR} GREATER 8))
    set(doclintstr "-Xdoclint:none")
endif()

javadoc(pki-javadoc
    SOURCEPATH
        ${CMAKE_SOURCE_DIR}/base/common/src/main/java
        ${CMAKE_SOURCE_DIR}/base/tools/src/main/java
        ${PKI_JAVADOC_SOURCEPATH}
    DEST
        ${CMAKE_CURRENT_BINARY_DIR}/javadoc/pki
    SUBPACKAGES
        com.netscape.cmsutil
        com.netscape.certsrv
        com.netscape.cmstools
        org.dogtagpki
        ${PKI_JAVADOC_SUBPACKAGES}
    CLASSPATH
        ${SLF4J_API_JAR} ${JAXB_API_JAR}
        ${COMMONS_CLI_JAR} ${COMMONS_LANG3_JAR}
        ${COMMONS_CODEC_JAR} ${COMMONS_IO_JAR}
        ${LDAPJDK_JAR}
        ${SERVLET_JAR} ${TOMCAT_CATALINA_JAR} ${TOMCAT_UTIL_JAR}
        ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
        ${JAXRS_API_JAR} ${JACKSON2_CORE_JAR}
        ${JACKSON2_ANNOTATIONS_JAR} ${JACKSON2_DATABIND_JAR} ${JACKSON2_JAXB_ANNOTATIONS_JAR}
        ${JAVAX_ANNOTATIONS_API_JAR}
        ${RESTEASY_JAXRS_JAR} ${RESTEASY_CLIENT_JAR}
        ${JSS_JAR}
        ${JSS_TOMCAT_JAR}
        ${JSS_TOMCAT_9_0_JAR}
        ${PKI_COMMON_JAR}
        ${PKI_TOOLS_JAR}
        ${PKI_JAVADOC_CLASSPATH}
    OPTIONS
        -windowtitle 'pki-javadoc'
        -doctitle '<h1>PKI Javadoc</h1>'
        -author
        -use
        -version
        -quiet
        ${doclintstr}
)

add_dependencies(javadoc pki-javadoc)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/javadoc/pki
    DESTINATION
        ${CMAKE_INSTALL_PREFIX}/share/javadoc
)
