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
execute_process(
    COMMAND
        echo ${Javac_VERSION_OUTPUT}
    COMMAND
        cut -f2 -d.
    OUTPUT_VARIABLE
        Javadoc_VERSION_MINOR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
message( STATUS "Javadoc_VERSION_MINOR = '${Javadoc_VERSION_MINOR}'" )

# REMINDER:  Eventually, it would almost certainly be safer to obtain the
#            'Javadoc_VERSION_MAJOR' number as well and perform the check
#            on "'Javadoc_VERSION_MAJOR'.'Javadoc_VERSION_MINOR'".
#
set(doclintstr "")
if(NOT (${Javadoc_VERSION_MINOR} LESS 8))
    set(doclintstr "-Xdoclint:none")
endif(NOT (${Javadoc_VERSION_MINOR} LESS 8))

# NOTE:  The following should generally be set to "".
#
#        For "alpha" releases, it will be set to ".a1", ".a2", etc.
#        For "beta" releases, it will be set to ".b1", ".b2", etc.
#
if (NOT DEFINED APPLICATION_VERSION_PHASE)
    set(JAVADOC_APPLICATION_VERSION ${APPLICATION_VERSION})
else (NOT DEFINED APPLICATION_VERSION_PHASE)
    set(JAVADOC_APPLICATION_VERSION ${APPLICATION_VERSION}.${APPLICATION_VERSION_PHASE})
endif(NOT DEFINED APPLICATION_VERSION_PHASE)

javadoc(pki-javadoc
    SOURCEPATH
        ${CMAKE_SOURCE_DIR}/base/util/src
        ${CMAKE_SOURCE_DIR}/base/common/src
        ${CMAKE_SOURCE_DIR}/base/java-tools/src
        ${CMAKE_SOURCE_DIR}/base/server/cms/src
    DEST
        ${CMAKE_CURRENT_BINARY_DIR}/javadoc/pki-${JAVADOC_APPLICATION_VERSION}
    SUBPACKAGES
        com.netscape.certsrv
        com.netscape.cms
        com.netscape.cmstools
        com.netscape.cmsutil
        org.dogtagpki
    CLASSPATH
        ${XALAN_JAR} ${XERCES_JAR}
        ${APACHE_COMMONS_CLI_JAR} ${APACHE_COMMONS_LANG_JAR}
        ${COMMONS_CODEC_JAR} ${COMMONS_HTTPCLIENT_JAR} ${COMMONS_IO_JAR}
        ${LDAPJDK_JAR} ${VELOCITY_JAR}
        ${JSS_JAR} ${SYMKEY_JAR}
        ${SERVLET_JAR} ${TOMCAT_CATALINA_JAR} ${TOMCAT_UTIL_JAR}
        ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
        ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR} ${RESTEASY_ATOM_PROVIDER_JAR} ${RESTEASY_CLIENT_JAR}
        ${PKI_CMSUTIL_JAR} ${PKI_CERTSRV_JAR} ${PKI_TOMCAT_JAR} ${PKI_CMS_JAR} ${PKI_TOOLS_JAR}
        ${NUXWDOG_JAR}
    OPTIONS
        -windowtitle 'pki-javadoc'
        -doctitle '<h1>PKI Javadoc</h1>'
        -author
        -use
        -version
        ${doclintstr}
    DEPENDS
        pki-cmsutil-jar pki-certsrv-jar pki-tomcat-jar pki-cms-jar pki-tools-jar
)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/javadoc/pki-${JAVADOC_APPLICATION_VERSION}
    DESTINATION
        ${CMAKE_INSTALL_PREFIX}/share/javadoc
)
