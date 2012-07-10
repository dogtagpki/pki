// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.common;

/**
 * This interface contains constants that are used
 * in the protocol between the configuration daemon
 * and UI configuration wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public interface ConfigConstants {

    public static final String TRUE = "true";
    public static final String FALSE = "false";
    public static final String OPTYPE = "opType";
    public static final String TASKID = "taskID";

    // Stages
    public static final String STAGES = "stages";
    public static final String STAGE_INTERNAL_DB = "stageInternalDB";
    public static final String STAGE_CONNECT_DB = "stageConnectDB";
    public static final String STAGE_SETUP_PORTS = "stageSetupPorts";
    public static final String STAGE_SETUP_ADMINISTRATOR = "stageSetupAdmin";
    public static final String STAGE_SETUP_SUBSYSTEMS = "stageSubsystems";
    public static final String STAGE_DATA_MIGRATION = "stageDataMigration";
    public static final String STAGE_CA_SELFSIGNED_CERT = "stageCASelfSignedCert";
    public static final String STAGE_CA_CERT_REQUEST = "stageCACertRequest";
    public static final String STAGE_CA_CERT_INSTALL = "stageCACertInstall";
    public static final String STAGE_RA_LOCAL_CERT = "stageRALocalCert";
    public static final String STAGE_RA_CERT_REQUEST = "stageRACertRequest";
    public static final String STAGE_RA_CERT_INSTALL = "stageRACertInstall";
    public static final String STAGE_KRA_LOCAL_CERT = "stageKRALocalCert";
    public static final String STAGE_KRA_CERT_REQUEST = "stageKRACertRequest";
    public static final String STAGE_KRA_CERT_INSTALL = "stageKRACertInstall";
    public static final String STAGE_SSL_LOCAL_CERT = "stageSSLLocalCert";
    public static final String STAGE_SSL_CERT_REQUEST = "stageSSLCertRequest";
    public static final String STAGE_SSL_CERT_INSTALL = "stageSSLCertInstall";
    public static final String STAGE_OCSP_LOCAL_CERT = "stageOCSPLocalCert";
    public static final String STAGE_OCSP_CERT_REQUEST = "stageOCSPCertRequest";
    public static final String STAGE_OCSP_CERT_INSTALL = "stageOCSPCertInstall";
    public static final String STAGE_CA_CERTCHAIN_IMPORT = "stageCACertChain";
    public static final String STAGE_RA_CERTCHAIN_IMPORT = "stageRACertChain";
    public static final String STAGE_OCSP_CERTCHAIN_IMPORT = "stageOCSPCertChain";
    public static final String STAGE_KRA_CERTCHAIN_IMPORT = "stageKRACertChain";
    public static final String STAGE_SSL_CERTCHAIN_IMPORT = "stageSSLCertChain";
    public static final String STAGE_OCSP_SERVICE_ADDED = "stageOCSPService";
    public static final String STAGE_CONFIG_WEBSERVER = "stageConfigWebserver";
    public static final String STAGE_REPLICATION_AGREEMENT = "stageReplicationAgreement";
    public static final String PR_ENABLE_REPLICATION = "enableReplication";

    public static final String CA_CERT_REQUEST = "CACertRequest";
    public static final String RA_CERT_REQUEST = "RACertRequest";
    public static final String OCSP_CERT_REQUEST = "OCSPCertRequest";
    public static final String KRA_CERT_REQUEST = "KRACertRequest";
    public static final String SSL_CERT_REQUEST = "SSLCertRequest";
    public static final String STAGE_CA_REQ_SUCCESS = "stageCAReqSuccess";
    public static final String STAGE_RA_REQ_SUCCESS = "stageRAReqSuccess";
    public static final String STAGE_KRA_REQ_SUCCESS = "stageKRAReqSuccess";
    public static final String STAGE_SSL_REQ_SUCCESS = "stageSSLReqSuccess";
    public static final String STAGE_OCSP_REQ_SUCCESS = "stageOCSPReqSuccess";

    public static final String STAGE_KRA_NM_SCHEME = "stageKRANMScheme";
    public static final String STAGE_CACLONING = "stageCACloning";
    public static final String STAGE_RACLONING = "stageRACloning";
    public static final String STAGE_KRACLONING = "stageKRACloning";
    public static final String STAGE_TKSCLONING = "stageTKSCloning";
    public static final String STAGE_SSLCLONING = "stageSSLCloning";
    public static final String STAGE_OCSPCLONING = "stageOCSPCloning";
    public static final String STAGE_CLONEMASTER = "stageCloneMaster";
    public static final String STAGE_UPDATE_DB_INFO = "stageUpdateDBInfo";

    public static final String CA_CERT_REQUEST_BACK = "CACertRequestBack";
    public static final String RA_CERT_REQUEST_BACK = "RACertRequestBack";
    public static final String OCSP_CERT_REQUEST_BACK = "OCSPCertRequestBack";
    public static final String KRA_CERT_REQUEST_BACK = "KRACertRequestBack";
    public static final String SSL_CERT_REQUEST_BACK = "SSLCertRequestBack";

    // Error messages
    public static final String PR_ERROR_MESSAGE = "errorMsg";

    // Certificate server instance
    public static final String PR_CERT_INSTANCE_NAME = "instanceID";

    // Admin server info
    public static final String PR_HOST = "host";
    public static final String PR_LDAP_DB_NAME = "ldapServerDB";
    public static final String PR_SERVER_ROOT = "serverRoot";
    public static final String PR_SIE_URL = "sieURL";
    public static final String PR_ADMIN_PASSWD = "AdminUserPassword";
    public static final String PR_ADMIN_UID = "adminUID";
    public static final String PR_ADMIN_DOMAIN = "adminDomain";
    public static final String PR_MACHINE_NAME = "machineName";

    public static final String PR_CA_OCSP_SERVICE = "CAOCSPService";

    // Daemon
    public static final String PR_DAEMON_PORT = "daemonPort";
    public static final String PR_DELETE_PASSWD_CONF = "deletePasswdConf";

    // Internal Database
    public static final String PR_DB_SCHEMA = "db.schema";
    public static final String PR_DB_MODE = "db.mode";
    public static final String PR_DB_PORT = "internaldb.ldapconn.port";
    public static final String PR_DB_HOST = "internaldb.ldapconn.host";
    public static final String PR_DB_BINDDN = "internaldb.ldapauth.bindDN";
    public static final String PR_DB_BINDPWD = "internaldb.ldapauth.bindPWPrompt";
    public static final String PR_DB_PWD = "db.password";
    public static final String PR_DB_LOCAL = "db.local";
    public static final String PR_DB_NAME = "db.instanceName";
    public static final String PR_CLONEDDB_NAME = "db.cloned.instanceName";
    public static final String PR_IS_DBCREATED = "db.isCreated";
    public static final String PR_IS_CLONEDDB_CREATED = "db.cloned.isCreated";
    public static final String PR_NEXT_AVAIL_PORT = "nextAvailPort";

    // Network Ports
    public static final String PR_ENABLE = "enabled";
    public static final String PR_EE_PORT = "eeGateway.http.port";
    public static final String PR_EE_SECURE_PORT = "eeGateway.https.port";
    public static final String PR_AGENT_PORT = "agentGateway.https.port";
    public static final String PR_RADM_PORT = "radm.https.port";
    public static final String PR_RADM_PORT_SETUP = "radm.port";
    public static final String PR_EE_PORT_ENABLE = "eeGateway.http.enable";
    public static final String PR_EE_PORTS_ENABLE = "eePortsEnable";

    // Certificate server administrator
    public static final String PR_CERT_ADMINNAME = "cert.admin.name";
    public static final String PR_CERT_ADMINUID = "cert.admin.uid";
    public static final String PR_CERT_ADMINPASSWD = "cert.admin.passwd";

    // Subsystems
    public static final String PR_SUBSYSTEMS = "subsystems";
    public static final String PR_CA = "ca";
    public static final String PR_RA = "ra";
    public static final String PR_KRA = "kra";
    public static final String PR_TKS = "tks";
    public static final String PR_OCSP = "ocsp";
    public static final String CA_HOST = "caHostname";
    public static final String CA_PORT = "caPortnum";
    public static final String CA_TIMEOUT = "caTimeout";
    public static final String KRA_HOST = "kraHostname";
    public static final String KRA_PORT = "kraPortnum";
    public static final String KRA_TIMEOUT = "kraTimeout";
    public static final String REMOTE_KRA_ENABLED = "remoteKRA";

    // Clone Master (CLA)
    public static final String CLA_HOST = "claHostname";
    public static final String CLA_PORT = "claPortnum";
    public static final String CLA_PORT_EE = "claPortnumEE";
    public static final String CLA_TIMEOUT = "claTimeout";
    public static final String CLONE_CA = "cloning";
    public static final String PR_CLONE_SETTING_DONE = "cloneSettingDone";

    // Data Migration
    public static final String PR_ENABLE_MIGRATION = "migrationEnable";
    public static final String PR_OUTPUT_PATH = "outputPath";
    public static final String PR_ADD_LDIF_PATH = "addLdifPath";
    public static final String PR_MOD_LDIF_PATH = "modLdifPath";
    public static final String PR_SIGNING_KEY_MIGRATION_TOKEN =
            "signingKeyMigrationToken";
    public static final String PR_SSL_KEY_MIGRATION_TOKEN =
            "sslKeyMigrationToken";
    public static final String PR_SIGNING_KEY_MIGRATION_TOKEN_PASSWD =
            "signingKeyMigrationTokenPasswd";
    public static final String PR_SIGNING_KEY_MIGRATION_TOKEN_SOPPASSWD =
            "signingKeyMigrationTokenSOPPasswd";
    public static final String PR_SSL_KEY_MIGRATION_TOKEN_PASSWD =
            "sslKeyMigrationTokenPasswd";
    public static final String PR_SSL_KEY_MIGRATION_TOKEN_SOPPASSWD =
            "sslKeyMigrationTokenSOPPasswd";
    public static final String PR_NUM_MIGRATION_WARNINGS =
            "numMigrationWarnings";
    public static final String PR_MIGRATION_WARNING = "migrationWarning";
    public static final String PR_CA_KEY_TYPE = "caKeyType";
    public static final String PR_LDAP_PASSWORD = "ldapPassword";
    public static final String PR_MIGRATION_PASSWORD = "migrationPassword";

    // Key and Cert
    public static final String PR_HARDWARE_SPLIT = "hardwareSplit";
    public static final String PR_TOKEN_LIST = "tokenList";
    public static final String PR_TOKEN_NAME = "tokenName";
    public static final String PR_SUBJECT_NAME = "subjectName";
    public static final String PR_CA_SUBJECT_NAME = "caSubjectName";
    public static final String PR_RA_SUBJECT_NAME = "raSubjectName";
    public static final String PR_OCSP_SUBJECT_NAME = "ocspSubjectName";
    public static final String PR_KRA_SUBJECT_NAME = "kraSubjectName";
    public static final String PR_SSL_SUBJECT_NAME = "sslSubjectName";
    public static final String PR_KEY_TYPE = "keyType";
    public static final String PR_KEY_LENGTH = "keyLength";
    public static final String PR_KEY_CURVENAME = "keyCurveName";
    public static final String PR_CERT_REQUEST = "certReq";
    public static final String PR_REQUEST_ID = "ReqID";
    public static final String PR_REQUEST_FORMAT = "ReqFormat";
    public static final String PR_REQUEST_PKCS10 = "PKCS10";
    public static final String PR_REQUEST_CMC = "CMC";
    public static final String PR_CERTIFICATE_TYPE = "certType";
    public static final String PR_CACERT_LOCALCA = "ca_isLocalCA";
    public static final String PR_RACERT_LOCALCA = "ra_isLocalCA";
    public static final String PR_KRACERT_LOCALCA = "kra_isLocalCA";
    public static final String PR_SSLCERT_LOCALCA = "ssl_isLocalCA";
    public static final String PR_OCSPCERT_LOCALCA = "ocsp_isLocalCA";
    public static final String PR_CERT_CONTENT_ORDER = "contentOrder";
    public static final String PR_CERTIFICATE_EXTENSION = "certificateExtension";
    public static final String CA_REQUEST_DISPLAYED = "caReqDisplayed";
    public static final String RA_REQUEST_DISPLAYED = "raReqDisplayed";
    public static final String OCSP_REQUEST_DISPLAYED = "ocspReqDisplayed";
    public static final String KRA_REQUEST_DISPLAYED = "kraReqDisplayed";
    public static final String SSL_REQUEST_DISPLAYED = "sslReqDisplayed";

    // KRA Storage Key Generation
    public static final String PR_KEY_LEN = "keyLength";
    public static final String PR_KEY_ALG = "keyAlg";
    public static final String PR_STORAGE_TOKEN_PWD = "storageTokenPwd";
    public static final String PR_STORAGE_HARDWARE = "storageHardware";

    // KRA Agents
    public static final String PR_AGENT_N = "n";
    public static final String PR_AGENT_M = "m";
    public static final String PR_AGENT_UID = "uid";
    public static final String PR_AGENT_PWD = "pwd";

    // Token Info
    public static final String PR_TOKEN_NAMES = "tokenNames";
    public static final String PR_TOKEN_INITIALIZED = "tokenInitialized";
    public static final String PR_TOKEN_LOGGED_IN = "tokenLoggedIn";
    public static final String PR_TOKEN_PASSWD = "tokenPasswd";
    public static final String PR_TOKEN_SOP = "sopPasswd";
    public static final String PR_CLONE_SUBSYSTEM = "cloneSubsystem";
    public static final String PR_CLONE_CA_TOKEN_NAME = "cloneCATokenName";
    public static final String PR_CLONE_OCSP_TOKEN_NAME = "cloneOCSPTokenName";
    public static final String PR_CLONE_RA_TOKEN_NAME = "cloneRATokenName";
    public static final String PR_CLONE_KRA_TOKEN_NAME = "cloneKRATokenName";
    public static final String PR_CLONE_STORAGE_TOKEN_NAME = "cloneStorageTokenName";
    public static final String PR_CLONE_SSL_TOKEN_NAME = "cloneSSLTokenName";
    public static final String PR_CLONE_CA_NICKNAME = "cloneCANickname";
    public static final String PR_CLONE_OCSP_NICKNAME = "cloneOCSPNickname";
    public static final String PR_CLONE_RA_NICKNAME = "cloneRANickname";
    public static final String PR_CLONE_KRA_NICKNAME = "cloneKRANickname";
    public static final String PR_CLONE_STORAGE_NICKNAME = "cloneStorageNickname";
    public static final String PR_CLONE_SSL_NICKNAME = "cloneSSLNickname";
    public static final String PR_TOKEN_LOGONLIST = "tokenLogonList";
    public static final String PR_TOKEN_LOGON_PWDS = "tokenLogonPasswords";
    public static final String PR_SUBSYSTEM = "subsystem";

    // Single Signon
    public static final String PR_SINGLE_SIGNON = "singleSignon";
    public static final String PR_SINGLE_SIGNON_PASSWORD = "singleSignonPwd";
    public static final String PR_SINGLE_SIGNON_PW_TAGS = "singleSignonPWTags";

    public static final String PR_CERT_CHAIN = "certChain";

    // Token Subsystem Info
    public static final String PR_CA_TOKEN = "caToken";
    public static final String PR_RA_TOKEN = "raToken";
    public static final String PR_KRA_TOKEN = "kraToken";
    public static final String PR_SSL_TOKEN = "sslToken";
    //public static final String PR_SUBSYSTEMS = "subsystems";

    // Key Length
    public static final String PR_RSA_MIN_KEYLENGTH = "RSAMinKeyLength";
    public static final String PR_CA_KEYTYPE = "ca_keyType";
    public static final String PR_HASH_TYPE = "hashType";
    public static final String PR_SIGNEDBY_TYPE = "signedBy";
    public static final String PR_NOTAFTER = "notAfter";
    public static final String PR_CA_O_COMPONENT = "caOComponent";
    public static final String PR_CA_C_COMPONENT = "caCComponent";
    public static final String PR_RA_O_COMPONENT = "raOComponent";
    public static final String PR_RA_C_COMPONENT = "raCComponent";
    public static final String PR_OCSP_O_COMPONENT = "ocspOComponent";
    public static final String PR_OCSP_C_COMPONENT = "ocspCComponent";

    // Subject DN
    public static final String PR_OU_COMPONENT = "OU_Component";
    public static final String PR_O_COMPONENT = "O_Component";
    public static final String PR_L_COMPONENT = "L_Component";
    public static final String PR_ST_COMPONENT = "ST_Component";
    public static final String PR_C_COMPONENT = "C_Component";

    // CA serial number
    public static final String PR_CA_SERIAL_NUMBER = "caSerialNumber";
    public static final String PR_CA_ENDSERIAL_NUMBER = "caEndSerialNumber";

    // KRA serial number
    public static final String PR_REQUEST_NUMBER = "requestNumber";
    public static final String PR_ENDREQUEST_NUMBER = "endRequestNumber";
    public static final String PR_SERIAL_REQUEST_NUMBER = "serialRequestNumber";

    // Cloning
    public static final String PR_CLONING_INSTANCE = "cloningInstance";
    public static final String PR_CLONE_CERTIFICATES = "clonedCertificates";

    // Cert request
    public static final String CA_EEPORT = "caEEPort";
    public static final String CA_EETYPE = "caEEType";

    // Certificate chain
    public static final String NOT_IMPORT_CHAIN = "notImportChain";

    public static final String OVERRIDE_VALIDITY = "overrideValidity";

    // request status: should be consistent with RequestStatus.java
    public static String BEGIN_STRING = "begin";
    public static String PENDING_STRING = "pending";
    public static String APPROVED_STRING = "approved";
    public static String SVC_PENDING_STRING = "svc_pending";
    public static String CANCELED_STRING = "canceled";
    public static String REJECTED_STRING = "rejected";
    public static String COMPLETE_STRING = "complete";

    public static String PR_CMS_SEED = "cmsSeed";

    public static String PR_WEB_SERVERROOT = "webServerRoot";
    public static String PR_USER_ID = "webUserId";

    public static final String PR_AGREEMENT_NAME_1 = "agreementName1";
    public static final String PR_REPLICATION_MANAGER_PASSWD_1 = "replicationManagerPwd1";
    public static final String PR_AGREEMENT_NAME_2 = "agreementName2";
    public static final String PR_REPLICATION_MANAGER_PASSWD_2 = "replicationManagerPwd2";
}
