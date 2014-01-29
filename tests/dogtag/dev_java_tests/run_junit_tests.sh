#!/bin/bash

# Include rhts environment
. /usr/bin/rhts-environment.sh
. /usr/share/beakerlib/beakerlib.sh
. /opt/rhqa_pki/rhcs-shared.sh
. /opt/rhqa_pki/pki-cert-cli-lib.sh
. /opt/rhqa_pki/env.sh

run_dev_junit_tests() {

    BIN_PATH="`pwd`/dev_java_tests/bin"
    RUNNING_WITH_BEAKER="TRUE"
    admin_cert_nickname="PKI Administrator for $CA_DOMAIN"
    nss_db_password="Secret123"
    chmod 777 $CA_ADMIN_CERT_LOCATION
    tmpDir=`mktemp -d`
    pushd $tmpDir
    nss_db_dir="$tmpDir/nssdb"
    mkdir $nss_db_dir
    importP12File $CA_ADMIN_CERT_LOCATION $CA_CLIENT_PKCS12_PASSWORD $nss_db_dir $nss_db_password $admin_cert_nickname
    install_and_trust_CA_cert $CA_SERVER_ROOT $nss_db_dir

    host=`hostname`

    export nss_db_dir nss_db_password admin_cert_nickname host CA_CLIENT_PKCS12_PASSWORD RUNNING_WITH_BEAKER

    ### Add all the pki packages and other dependent pki packages to the class path
    CLASSPATH=/usr/share/java/junit4.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/pki/*
    CLASSPATH=$CLASSPATH:/usr/lib64/jss/jss4.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/httpcomponents/httpclient.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/httpcomponents/httpcore.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/jackson-annotations.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/jackson/jackson-core-asl.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/jackson-core.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/jackson-databind.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/jackson-jaxrs-providers/jackson-jaxrs-base.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/jackson/jackson-jaxrs.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/jackson-jaxrs-providers/jackson-jaxrs-json-provider.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/jackson/jackson-mapper-asl.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/jackson-module-jaxb-annotations.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/jackson/jackson-mrbean.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/jackson/jackson-smile.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/jackson/jackson-xc.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/resteasy/jaxrs-api.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/resteasy/resteasy-atom-provider.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/resteasy/resteasy-jaxb-provider.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/resteasy/resteasy-jaxrs.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/resteasy/resteasy-jaxrs-jandex.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/resteasy/resteasy-jackson-provider.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/apache-commons-cli.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/apache-commons-codec.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/apache-commons-logging.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/commons-codec.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/commons-httpclient.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/idm-console-base-1.1.7.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/idm-console-mcc.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/idm-console-nmclf.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/jakarta-commons-httpclient.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/jaxb-api.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/ldapjdk.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/apache-commons-lang.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/istack-commons-runtime.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/scannotation.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/servlet.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/velocity.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/xerces-j2.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/xml-commons-apis.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/tomcat/catalina.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/tomcat/tomcat-util.jar
    CLASSPATH=$CLASSPATH:/usr/share/java/commons-io.jar
    CLASSPATH=$CLASSPATH:$BIN_PATH
    export CLASSPATH

    cd $BIN_PATH

    echo "running the Java tests"
    java org.junit.runner.JUnitCore BeakerTestSuite > /dev/null 2>&1

    chmod +x java-tests-script.sh

    sh java-tests-script.sh

    #rlJournalEnd

}
