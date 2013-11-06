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
    export CLASSPATH=/usr/share/java/junit4.jar:/usr/share/java/pki/*:/usr/lib64/jss/jss4.jar:/usr/share/java/httpcomponents/httpclient.jar:/usr/share/java/httpcomponents/httpcore.jar:/usr/share/java/resteasy/jaxrs-api.jar:/usr/share/java/resteasy/resteasy-atom-provider.jar:/usr/share/java/resteasy/resteasy-jaxb-provider.jar:/usr/share/java/resteasy/resteasy-jaxrs.jar:/usr/share/java/resteasy/resteasy-jaxrs-jandex.jar:/usr/share/java/resteasy/resteasy-jettison-provider.jar:/usr/share/java/apache-commons-cli.jar:/usr/share/java/apache-commons-codec.jar:/usr/share/java/apache-commons-logging.jar:/usr/share/java/commons-codec.jar:/usr/share/java/commons-httpclient.jar:/usr/share/java/idm-console-base-1.1.7.jar:/usr/share/java/idm-console-mcc.jar:/usr/share/java/idm-console-nmclf.jar:/usr/share/java/jakarta-commons-httpclient.jar:/usr/share/java/jaxb-api.jar:/usr/share/java/ldapjdk.jar:/usr/share/java/apache-commons-lang.jar:/usr/share/java/istack-commons-runtime.jar:/usr/share/java/scannotation.jar:/usr/share/java/servlet.jar:/usr/share/java/velocity.jar:/usr/share/java/xerces-j2.jar:/usr/share/java/xml-commons-apis.jar:/usr/share/java/tomcat/catalina.jar:/usr/share/java/tomcat/tomcat-util.jar:/usr/share/java/commons-io.jar:$BIN_PATH

    cd $BIN_PATH

    echo "running the Java tests"
    java org.junit.runner.JUnitCore BeakerTestSuite > /dev/null 2>&1

    chmod +x java-tests-script.sh

    sh java-tests-script.sh

    #rlJournalEnd

}
