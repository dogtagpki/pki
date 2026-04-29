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

# Check v1 API status
if(NOT DEFINED V1_API_STATUS)
    set(V1_API_STATUS "deprecated")
endif()
# Always set as cache variable to make it available to all subdirectories
set(V1_API_STATUS "${V1_API_STATUS}" CACHE STRING "v1 API status: enabled, deprecated, disabled, dropped" FORCE)
message(STATUS "V1_API_STATUS = ${V1_API_STATUS}")

if("${V1_API_STATUS}" STREQUAL "dropped")
    # v1 dropped: exclude v1-specific packages from javadoc
    message(STATUS "v1 API dropped: excluding v1 packages from javadoc")
    # Don't include com.netscape.certsrv or org.dogtagpki (which are mostly v1 Resource interfaces)
    set(v1_subpackages "org.dogtagpki")
    # Exclude v1-specific packages (both client and server)
    # Only exclude v1 REST packages, not entire subsystem packages
    set(exclude_packages
        "com.netscape.certsrv"
        "com.netscape.cms.servlet"
        "org.dogtagpki.server.rest.v1"
        "org.dogtagpki.server.ca.rest.v1"
        "org.dogtagpki.server.kra.rest.v1"
        "org.dogtagpki.server.ocsp.rest.v1"
        "org.dogtagpki.server.tks.rest.v1"
        "org.dogtagpki.server.tps.rest.v1"
    )
    # Don't include JAX-RS jars - they're not available when v1 is dropped
    # and javadoc will skip type checking for excluded packages
    set(jaxrs_classpath "")
    # Ignore source errors in excluded packages (transformed code references jakarta.ws.rs but jars have javax.ws.rs)
    set(v1_javadoc_opts "--ignore-source-errors")
else()
    # v1 enabled/deprecated/disabled: include all packages
    message(STATUS "v1 API ${V1_API_STATUS}: including all packages in javadoc")
    set(v1_subpackages "com.netscape.certsrv" "org.dogtagpki")
    set(exclude_packages "")
    set(jaxrs_classpath ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR})
    set(v1_javadoc_opts "")
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
        com.netscape.cmstools
        ${v1_subpackages}
        ${PKI_JAVADOC_SUBPACKAGES}
    EXCLUDE
        ${exclude_packages}
    CLASSPATH
        ${SLF4J_API_JAR} ${JAXB_API_JAR}
        ${COMMONS_CLI_JAR} ${COMMONS_LANG3_JAR}
        ${COMMONS_CODEC_JAR} ${COMMONS_IO_JAR}
        ${LDAPJDK_JAR}
        ${SERVLET_JAR} ${TOMCAT_CATALINA_JAR} ${TOMCAT_UTIL_JAR}
        ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
        ${jaxrs_classpath}
        ${JACKSON_CORE_JAR}
        ${JACKSON_ANNOTATIONS_JAR}
        ${JACKSON_DATABIND_JAR}
        ${JACKSON_MODULE_JAXB_ANNOTATIONS_JAR}
        ${JAKARTA_ANNOTATION_API_JAR}
        ${JSS_JAR}
        ${JSS_TOMCAT_JAR}
        ${JSS_TOMCAT_9_0_JAR}
        ${JSS_TOMCAT_10_1_JAR}
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
        ${v1_javadoc_opts}
)

add_dependencies(javadoc pki-javadoc)

install(
    DIRECTORY
        ${CMAKE_CURRENT_BINARY_DIR}/javadoc/pki
    DESTINATION
        ${CMAKE_INSTALL_PREFIX}/share/javadoc
)
