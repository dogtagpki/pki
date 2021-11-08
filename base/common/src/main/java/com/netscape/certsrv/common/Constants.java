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
 * This interface contains constants that are shared
 * by certificate server and its client SDK.
 *
 * @author Jack Pan-Chen
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public interface Constants {

    /*=======================================================
     * MESSAGE FORMAT CONSTANTS
     *=======================================================*/
    public static final String PASSWORDTYPE = "PasswordField";
    public static final String TEXTTYPE = "TextField";
    public static final String CHECKBOXTYPE = "CheckBox";
    public static final String COMBOTYPE = "ComboBox";
    public static final String TRUE = "true";
    public static final String FALSE = "false";
    public static final String VIEW = "view";
    public static final String EDIT = "edit";

    public static final String OP_TYPE = "OP_TYPE";
    public static final String OP_SCOPE = "OP_SCOPE";

    //STATIC RESOURCE IDENTIFIERS
    public static final String RS_ID = "RS_ID";
    public static final String RS_ID_CONFIG = "RS_ID_CONFIG";
    public static final String RS_ID_ORDER = "RS_ID_ORDER";

    //STATIC UI TYPE
    public static final String TYPE_PASSWORD = "password";

    /**********************************************************
     * PROPERTY NAME LISTED BELOW
     **********************************************************/

    /*========================================================
     * General
     *========================================================*/
    public static final String PR_PORT = "port";
    public static final String PR_SSLPORT = "sslPort";

    /*========================================================
     * Tasks
     *========================================================*/
    public static final String PR_SERVER_START = "start";
    public static final String PR_SERVER_STOP = "stop";
    public static final String PR_SERVER_RESTART = "restart";

    /*========================================================
     * Networks
     *========================================================*/
    public static final String PR_ADMIN_S_PORT = "admin.https.port";
    public static final String PR_AGENT_S_PORT = "agent.https.port";
    public static final String PR_GATEWAY_S_PORT = "gateway.https.port";
    public static final String PR_GATEWAY_PORT = "gateway.http.port";
    public static final String PR_DOC_ROOT = "docroot";
    public static final String PR_ADMIN_S_BACKLOG = "admin.https.backlog";
    public static final String PR_AGENT_S_BACKLOG = "agent.https.backlog";
    public static final String PR_GATEWAY_S_BACKLOG = "gateway.https.backlog";
    public static final String PR_GATEWAY_BACKLOG = "gateway.http.backlog";
    public static final String PR_GATEWAY_PORT_ENABLED =
            "gateway.http.enable";
    public static final String PR_MASTER_AGENT_PORT = "master.ca.agent.port";
    public static final String PR_MASTER_AGENT_HOST = "master.ca.agent.host";

    /*========================================================
     * SMTP
     *========================================================*/
    public static final String PR_SERVER_NAME = "server";

    /*========================================================
     * SNMP
     *========================================================*/
    public static final String PR_SNMP_ENABLED = "on";
    public static final String PR_SNMP_MASTER_HOST = "master.host";
    public static final String PR_SNMP_MASTER_PORT = "master.port";
    public static final String PR_SNMP_DESC = "desc";
    public static final String PR_SNMP_ORGN = "orgn";
    public static final String PR_SNMP_LOC = "loc";
    public static final String PR_SNMP_CONTACT = "contact";

    /*========================================================
     * Self Tests
     *========================================================*/
    public static final String PR_RUN_SELFTESTS_ON_DEMAND = "run";
    public static final String PR_RUN_SELFTESTS_ON_DEMAND_CLASS = "class";
    public static final String PR_RUN_SELFTESTS_ON_DEMAND_CONTENT = "runContent";

    /*========================================================
     * Users and Groups
     *========================================================*/

    //group properties
    public static final String PR_GROUP_DESC = "desc";
    public static final String PR_GROUP_USER = "user";
    public static final String PR_GROUP_GROUP = "group";

    //user properties
    public static final String PR_USER_FULLNAME = "fullname";
    public static final String PR_USER_PASSWORD = "password";
    public static final String PR_USER_EMAIL = "email";
    public static final String PR_USER_PHONE = "phone";
    public static final String PR_USER_STATE = "state";
    public static final String PR_USER_CERT = "cert";
    public static final String PR_USER_GROUP = "groups";
    public static final String PR_MULTIROLES = "multiroles";

    /*========================================================
     * Authentication
     *========================================================*/
    public static final String PR_PING = "ping";
    public static final String PR_AUTH_CLASS = "class";
    public static final String PR_AUTH_IMPL_NAME = "implName";
    public static final String PR_AUTH_HOST = "ldapconn.host";
    public static final String PR_AUTH_PORT = "ldapconn.port";
    public static final String PR_AUTH_ADMIN_DN = "ldapauth.bindDN";
    public static final String PR_AUTH_ADMIN_PWD = "ldapauth.bindPassword";

    /*========================================================
     * Job Scheduler
     *========================================================*/
    public static final String PR_JOBS_CLASS = "class";
    public static final String PR_JOBS_IMPL_NAME = "implName";
    public static final String PR_JOBS_FREQUENCY = "frequency";

    /*========================================================
     * Notification
     *========================================================*/
    public static final String PR_NOTIFICATION_FORM_NAME = "emailTemplate";
    public static final String PR_NOTIFICATION_SUBJECT =
            "emailSubject";
    public static final String PR_NOTIFICATION_SENDER = "senderEmail";
    public static final String PR_NOTIFICATION_RECEIVER = "recipientEmail";

    /*========================================================
     * Logs
     *========================================================*/
    public static final String PR_LOG_IMPL_NAME = "implName";
    public static final String PR_EXT_PLUGIN_IMPLTYPE_LOG = "log";
    public static final String PR_LOG_CLASS = "class";
    public static final String PR_LOG_INSTANCE = "instanceName";
    public static final String PR_LOG_ONE = "entry";
    public static final String PR_LOG_ENTRY = "maxentry";
    public static final String PR_LOG_SOURCE = "source";
    public static final String PR_LOG_LEVEL = "level";
    public static final String PR_LOG_ENABLED = "on";
    public static final String PR_LOG_BUFFERSIZE = "bufferSize";
    public static final String PR_LOG_EXPIRED_TIME = "expirationTime";
    public static final String PR_LOG_FILENAME = "fileName";
    public static final String PR_LOG_FLUSHINTERVAL = "flushInterval";
    public static final String PR_LOG_MAXFILESIZE = "maxFileSize";
    public static final String PR_LOG_ROLLEROVER_INTERVAL = "rolloverInterval";
    public static final String PR_LOG_TYPE = "type";
    public static final String PR_LOGSOURCE_KRA = "KRA";
    public static final String PR_LOGSOURCE_RA = "RA";
    public static final String PR_LOGSOURCE_CA = "CA";
    public static final String PR_LOGSOURCE_HTTP = "HTTP";
    public static final String PR_LOGSOURCE_DB = "DB";
    public static final String PR_LOGSOURCE_AUTH = "AUTH";
    public static final String PR_LOGSOURCE_ADMIN = "ADMIN";
    public static final String PR_LOG_NAME = "logname";
    public static final String PR_CURRENT_LOG = "current";

    public static final String PR_AUTO_CRL = "auto";
    public static final String PR_LOG_SIGNED_AUDIT = "SignedAudit";
    public static final String PR_LOG_TRANSACTIONS = "Transactions";
    public static final String PR_LOG_SYSTEM = "System";

    public static final String PR_DEBUG_LOG_LEVEL = "debug.level";

    /*========================================================
     * LDAP Publishing
     *========================================================*/

    // publishing properties
    public static final String PR_BASIC_AUTH = "BasicAuth";
    public static final String PR_SSL_AUTH = "SslClientAuth";
    public static final String PR_AUTH_TYPE = "ldapauth.authtype";
    public static final String PR_BINDPWD_PROMPT = "ldapauth.bindPWPrompt";
    public static final String PR_CERT_NAMES = "ldapauth.nicknames";
    public static final String PR_LDAP_CLIENT_CERT = "ldapauth.clientCertNickname";
    public static final String PR_DIRECTORY_MANAGER_PWD = "directoryManagerPwd";

    // crl settings
    public static final String PR_ENABLE_CRL = "enableCRLUpdates";
    public static final String PR_UPDATE_SCHEMA = "updateSchema";
    public static final String PR_EXTENDED_NEXT_UPDATE = "extendedNextUpdate";
    public static final String PR_UPDATE_ALWAYS = "alwaysUpdate";
    public static final String PR_ENABLE_DAILY = "enableDailyUpdates";
    public static final String PR_DAILY_UPDATES = "dailyUpdates";
    public static final String PR_ENABLE_FREQ = "enableUpdateInterval";
    public static final String PR_UPDATE_FREQ = "autoUpdateInterval";
    public static final String PR_GRACE_PERIOD = "nextUpdateGracePeriod";
    public static final String PR_NEXT_AS_THIS_EXTENSION = "nextAsThisUpdateExtension";
    public static final String PR_ENABLE_CACHE = "enableCRLCache";
    public static final String PR_CACHE_FREQ = "cacheUpdateInterval";
    public static final String PR_CACHE_RECOVERY = "enableCacheRecovery";
    public static final String PR_CACHE_TESTING = "enableCacheTesting";
    public static final String PR_EXTENSIONS = "allowExtensions";
    public static final String PR_INCLUDE_EXPIREDCERTS = "includeExpiredCerts";
    public static final String PR_INCLUDE_EXPIREDCERTS_ONEEXTRATIME = "includeExpiredCertsOneExtraTime";
    public static final String PR_CA_CERTS_ONLY = "caCertsOnly";
    public static final String PR_PROFILE_CERTS_ONLY = "profileCertsOnly";
    public static final String PR_PROFILE_LIST = "profileList";
    public static final String PR_SIGNING_ALGORITHM = "signingAlgorithm";
    public static final String PR_MD2_RSA = "MD2withRSA";
    public static final String PR_MD5_RSA = "MD5withRSA";

    //Should be replaced with SHA-2
    @Deprecated(since="11.0.1", forRemoval=true)
    public static final String PR_SHA1_RSA = "SHA1withRSA";
    @Deprecated(since="11.0.1", forRemoval=true)
    public static final String PR_SHA1_DSA = "SHA1withDSA";

    public static final String PR_DESCRIPTION = "description";
    public static final String PR_CLASS = "class";

    // ldap settings
    public static final String PR_ENABLE = "enable";
    public static final String PR_PUBLISHING_ENABLE = "publishingEnable";
    public static final String PR_HOST_NAME = "ldapconn.host";
    public static final String PR_SECURE_PORT_ENABLED = "ldapconn.secureConn";
    public static final String PR_LDAP_PORT = "ldapconn.port";
    public static final String PR_LDAP_VERSION = "ldapconn.version";
    public static final String PR_BIND_DN = "ldapauth.bindDN";
    public static final String PR_BIND_PASSWD = "ldapauth.bindPassword";
    public static final String PR_BIND_PASSWD_AGAIN = "bindPasswdAgain";
    public static final String PR_LDAP_MAX_CONNS = "maxConns";
    public static final String PR_LDAP_MIN_CONNS = "minConns";
    public static final String PR_PUBLISHING_QUEUE_ENABLE = "queue.enable";
    public static final String PR_PUBLISHING_QUEUE_THREADS = "queue.maxNumberOfThreads";
    public static final String PR_PUBLISHING_QUEUE_PAGE_SIZE = "queue.pageSize";
    public static final String PR_PUBLISHING_QUEUE_PRIORITY = "queue.priorityLevel";
    public static final String PR_PUBLISHING_QUEUE_STATUS = "queue.saveStatus";

    public static final String PR_BASE_DN = "baseDN";
    public static final String PR_DNCOMPS = "dnComps";
    public static final String PR_FILTERCOMPS = "filterComps";

    // ldap connection test
    public static final String PR_CONN_INITED = "connInited";
    public static final String PR_CONN_INIT_FAIL = "connInitFail";
    public static final String PR_CONN_OK = "connOk";
    public static final String PR_CONN_FAIL = "connFail";
    public static final String PR_AUTH_OK = "authOk";
    public static final String PR_AUTH_FAIL = "authFail";
    public static final String PR_SAVE_OK = "saveOk";
    public static final String PR_SAVE_NOT = "saveOrNot";

    /*========================================================
     * Plugin
     *========================================================*/
    public static final String PR_PLUGIN_IMP = "imp";
    public static final String PR_PLUGIN_INSTANCE = "instance";

    /*========================================================
     * Policy
     *========================================================*/
    public static final String PR_POLICY_CLASS = "class";
    public static final String PR_POLICY_IMPL_NAME = "implName";
    public static final String PR_CRLDP_NAME = "crldpName";
    public static final String PR_POLICY_DESC = "desc";
    public static final String PR_POLICY_ORDER = "order";
    public static final String PR_POLICY_ENABLE = "enable";
    public static final String PR_POLICY_PREDICATE = "predicate";

    /*========================================================
     * Publish
     *========================================================*/
    public static final String PR_PUBLISHER = "publisher";
    public static final String PR_PUBLISHER_CLASS = "class";
    public static final String PR_PUBLISHER_IMPL_NAME = "implName";
    public static final String PR_PUBLISHER_DESC = "desc";
    public static final String PR_PUBLISHER_ORDER = "order";
    public static final String PR_PUBLISHER_ENABLE = "enable";

    public static final String PR_MAPPER = "mapper";
    public static final String PR_MAPPER_CLASS = "class";
    public static final String PR_MAPPER_IMPL_NAME = "implName";
    public static final String PR_MAPPER_DESC = "desc";
    public static final String PR_MAPPER_ORDER = "order";
    public static final String PR_MAPPER_ENABLE = "enable";

    public static final String PR_RULE = "rule";
    public static final String PR_RULE_CLASS = "class";
    public static final String PR_RULE_IMPL_NAME = "implName";
    public static final String PR_RULE_DESC = "desc";
    public static final String PR_RULE_ORDER = "order";
    public static final String PR_RULE_ENABLE = "enable";

    public static final String PR_CRLEXT = "crlExt";
    public static final String PR_CRLEXT_CLASS = "class";
    public static final String PR_CRLEXT_IMPL_NAME = "implName";
    public static final String PR_CRLEXT_DESC = "desc";
    public static final String PR_CRLEXT_ORDER = "order";
    public static final String PR_CRLEXT_ENABLE = "enable";

    public static final String PR_OCSPSTORE_IMPL_NAME = "implName";

    /*========================================================
     * Registration Authority
     *========================================================*/
    public static final String PR_EE_ENABLED = "eeEnabled";
    public static final String PR_OCSP_ENABLED = "ocspEnabled";
    public static final String PR_RA_ENABLED = "raEnabled";
    public static final String PR_RENEWAL_ENABLED = "renewal.enabled";
    public static final String PR_RENEWAL_VALIDITY = "renewal.validity";
    public static final String PR_RENEWAL_EMAIL = "renewal.email";
    public static final String PR_RENEWAL_EXPIREDNOTIFIEDENABLED =
            "renewal.expired.notification.enabled";
    public static final String PR_RENEWAL_NUMNOTIFICATION =
            "renewal.numNotification";
    public static final String PR_RENEWAL_INTERVAL = "renewal.interval";
    public static final String PR_SERVLET_CLASS = "class";
    public static final String PR_SERVLET_URI = "uri";
    public static final String PR_IMPL_NAME = "implName";
    public static final String PR_LOCAL = "local";
    public static final String PR_ID = "id";
    public static final String PR_HOST = "host";
    public static final String PR_URI = "uri";
    public static final String PR_ENABLED = "enable";

    /*========================================================
     * Certificate Authority
     *========================================================*/
    public static final String PR_VALIDITY = "validity";
    public static final String PR_DEFAULT_ALGORITHM = "defaultSigningAlgorithm";
    public static final String PR_ALL_ALGORITHMS = "allSigningAlgorithms";
    public static final String PR_SERIAL = "startSerialNumber";
    public static final String PR_MAXSERIAL = "maxSerialNumber";
    public static final String PR_SN_MANAGEMENT = "serialNumberManagement";
    public static final String PR_RANDOM_SN = "randomSerialNumbers";

    /*========================================================
     * Access Control
     *========================================================*/
    public static final String PR_ACL_OPS = "aclOperations";
    public static final String PR_ACI = "aci";
    public static final String PR_ACL_CLASS = "class";
    public static final String PR_ACL_DESC = "desc";
    public static final String PR_ACL_RIGHTS = "rights";

    /*========================================================
     * Key Recovery
     *========================================================*/
    public static final String PR_AUTO_RECOVERY_ON = "autoRecoveryOn";
    public static final String PR_RECOVERY_N = "recoveryN";
    public static final String PR_RECOVERY_M = "recoveryM";
    public static final String PR_OLD_RECOVERY_AGENT = "oldRecoveryAgent";
    public static final String PR_RECOVERY_AGENT = "recoveryAgent";
    public static final String PR_OLD_AGENT_PWD = "oldAgentPwd";
    public static final String PR_AGENT_PWD = "agentPwd";
    public static final String PR_NO_OF_REQUIRED_RECOVERY_AGENTS = "noOfRequiredRecoveryAgents";

    /*========================================================
     * Status
     *========================================================*/
    public static final String PR_STAT_STARTUP = "startup";
    public static final String PR_STAT_TIME = "time";
    public static final String PR_STAT_VERSION = "cms.version";
    public static final String PR_STAT_INSTALLDATE = "installDate";
    public static final String PR_STAT_INSTANCEID = "instanceId";

    /*========================================================
     * Server Instance
     *========================================================*/
    public static final String PR_INSTALL = "install";
    public static final String PR_INSTANCES_INSTALL = "instancesInstall";
    public static final String PR_CA_INSTANCE = "ca";
    public static final String PR_OCSP_INSTANCE = "ocsp";
    public static final String PR_RA_INSTANCE = "ra";
    public static final String PR_KRA_INSTANCE = "kra";
    public static final String PR_TKS_INSTANCE = "tks";

    /*
     * Certificate info
     */
    public static final String PR_CA_SIGNING_NICKNAME = "caSigningCert";
    public static final String PR_PKCS10 = "pkcs10";
    public static final String PR_CERT_SUBJECT_NAME = "certSubjectName";
    public static final String PR_ISSUER_NAME = "issuerName";
    public static final String PR_SERIAL_NUMBER = "serialNumber";
    public static final String PR_BEFORE_VALIDDATE = "beforeValidDate";
    public static final String PR_AFTER_VALIDDATE = "afterValidDate";
    public static final String PR_CERT_FINGERPRINT = "certFingerPrint";
    public static final String PR_SIGNATURE_ALGORITHM = "signatureAlg";
    public static final String PR_ALGORITHM_ID = "algorithmId";
    public static final String PR_NICKNAME = "nickname";
    public static final String PR_ADD_CERT = "addCert";
    public static final String PR_CERT_CONTENT = "certContent";

    /*
     * Certificate type
     */
    public static final String PR_CERTIFICATE_TYPE = "certType";
    public static final String PR_CERTIFICATE_SUBTYPE = "certSubType";
    public static final String PR_CA_SIGNING_CERT = "caSigningCert";
    public static final String PR_RA_SIGNING_CERT = "raSigningCert";
    public static final String PR_OCSP_SIGNING_CERT = "ocspSigningCert";
    public static final String PR_KRA_TRANSPORT_CERT = "kraTransportCert";
    public static final String PR_SERVER_CERT = "serverCert";
    public static final String PR_SUBSYSTEM_CERT = "subsystemCert";
    public static final String PR_SERVER_CERT_RADM = "serverCertRadm";
    public static final String PR_CROSS_CERT = "crossCert";
    public static final String PR_OTHER_CERT = "otherCert";
    public static final String PR_SERVER_CERT_CHAIN = "serverCertChain";
    public static final String PR_TRUSTED_CA_CERT = "trustedCACert";
    public static final String PR_TRUSTED_CERT = "trustedCert";
    public static final String PR_AUDIT_SIGNING_CERT = "auditSigningCert";

    /*
     * Extensions
     */
    public static final String PR_VALIDITY_PERIOD = "validityPeriod";
    public static final String PR_BEGIN_YEAR = "beginYear";
    public static final String PR_BEGIN_MONTH = "beginMonth";
    public static final String PR_BEGIN_DATE = "beginDate";
    public static final String PR_BEGIN_HOUR = "beginHour";
    public static final String PR_BEGIN_MIN = "beginMin";
    public static final String PR_BEGIN_SEC = "beginSec";
    public static final String PR_AFTER_YEAR = "afterYear";
    public static final String PR_AFTER_MONTH = "afterMonth";
    public static final String PR_AFTER_DATE = "afterDate";
    public static final String PR_AFTER_HOUR = "afterHour";
    public static final String PR_AFTER_MIN = "afterMin";
    public static final String PR_AFTER_SEC = "afterSec";
    public static final String PR_AIA = "aia";
    public static final String PR_AKI = "aki";
    public static final String PR_OCSP_SIGNING = "ocspSigning";
    public static final String PR_OCSP_NOCHECK = "ocspNoCheck";
    public static final String PR_SKI = "ski";
    public static final String PR_KEY_USAGE = "keyUsage";
    public static final String PR_DER_EXTENSION = "derExtension";
    public static final String PR_IS_CA = "isCA";
    public static final String PR_CERT_LEN = "certLen";
    public static final String PR_SSL_CLIENT_BIT = "sslClientBit";
    public static final String PR_SSL_SERVER_BIT = "sslServerBit";
    public static final String PR_SSL_MAIL_BIT = "sslMailBit";
    public static final String PR_SSL_CA_BIT = "sslCABit";
    public static final String PR_OBJECT_SIGNING_BIT = "objectSigningBit";
    public static final String PR_MAIL_CA_BIT = "mailCABit";
    public static final String PR_OBJECT_SIGNING_CA_BIT = "objectSigningCABit";
    public static final String PR_TIMESTAMPING_BIT = "timeStampingBit";
    public static final String PR_CA_KEYID = "caKeyid";
    public static final String PR_CA_KEYPAIR = "caKeyPair";

    /**
     * Trust database
     */
    public static final String PR_TRUST = "trust";

    /*========================================================
     * Security
     *========================================================*/

    //functionality
    public static final String PR_CERT_SERVER = "SERVER";
    public static final String PR_CERT_ADMIN = "ADMIN";
    public static final String PR_CERT_AGENT = "AGENT";
    public static final String PR_CERT_EE = "EE";
    public static final String PR_CERT_CA = "CA";
    public static final String PR_CERT_RA = "RA";
    public static final String PR_CERT_POA = "POA";
    public static final String PR_CERT_TRANS = "TRANS";

    // key and certificate management
    public static final String PR_OPERATION_TYPE = "operationtype";
    public static final String PR_INSTALL_TYPE = "install";
    public static final String PR_REQUEST_TYPE = "request";
    //public static final String PR_CA_SIGNING_CERT = "cacert";
    //public static final String PR_SERVER_CERT = "servercert";
    public static final String PR_CLIENT_CERT = "clientcert";
    public static final String PR_TOKEN_NAME = "tokenName";
    public static final String PR_TOKEN_PASSWD = "tokenPwd";
    public static final String PR_KEY_LENGTH = "keyLength";
    public static final String PR_KEY_CURVENAME = "keyCurveName";
    public static final String PR_SIGNEDBY_TYPE = "signedBy";
    public static final String PR_KEY_TYPE = "keyType";
    public static final String PR_PQGPARAMS = "pqgParams";
    public static final String PR_CERT_REQUEST = "certReq";
    public static final String PR_CERT_REQUEST_DIR = "certReqDir";
    public static final String PR_CERT_CONFIG_DIR = "certConfigDir";
    public static final String PR_IMPORT_CERT = "importCert";
    public static final String PR_SUBJECT_NAME = "subjectName";
    public static final String PR_CSR = "csr";

    //encryption

    /* Cipher Version: domestic or export */
    public static final String PR_CIPHER_VERSION = "cipherversion";
    public static final String PR_CIPHER_VERSION_DOMESTIC = "cipherdomestic";
    public static final String PR_CIPHER_VERSION_EXPORT = "cipherexport";

    /* Cipher Fortezza: true, false */
    public static final String PR_CIPHER_FORTEZZA = "cipherfortezza";

    /* Token and Certificates */
    public static final String PR_TOKEN_LIST = "tokenlist";
    public static final String PR_TOKEN_PREFIX = "token_";
    public static final String PR_KEY_LIST = "keylist";

    /* SSL Cipher Preferences */
    public static final String PR_CIPHER_PREF = "cipherpref";

    /* SSL EC Type */
    public static final String PR_ECTYPE = "ectype";

    /* values for SSL cipher preferences */
    public static final String PR_SSL2_RC4_128_WITH_MD5 = "rc4";
    public static final String PR_SSL2_RC4_128_EXPORT40_WITH_MD5 = "rc4export";
    public static final String PR_SSL2_RC2_128_CBC_WITH_MD5 = "rc2";
    public static final String PR_SSL2_RC2_128_CBC_EXPORT40_WITH_MD5 = "rc2export";
    public static final String PR_SSL2_DES_64_CBC_WITH_MD5 = "des";
    public static final String PR_SSL2_DES_192_EDE3_CBC_WITH_MD5 = "desede3";
    public static final String PR_SSL3_RSA_WITH_NULL_MD5 = "rsa_null_md5";
    public static final String PR_SSL3_RSA_EXPORT_WITH_RC4_40_MD5 = "rsa_rc4_40_md5";
    public static final String PR_SSL3_RSA_WITH_RC4_128_MD5 = "rsa_rc4_128_md5";
    public static final String PR_SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = "rsa_rc2_40_md5";
    public static final String PR_SSL3_RSA_WITH_DES_CBC_SHA = "rsa_des_sha";
    public static final String PR_SSL3_RSA_WITH_3DES_EDE_CBC_SHA = "rsa_3des_sha";
    public static final String PR_SSL3_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA = "fortezza";
    public static final String PR_SSL3_FORTEZZA_DMS_WITH_RC4_128_SHA = "fortezza_rc4_128_sha";
    public static final String PR_SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA = "rsa_fips_3des_sha";
    public static final String PR_SSL_RSA_FIPS_WITH_DES_CBC_SHA = "rsa_fips_des_sha";
    public static final String PR_TLS_RSA_EXPORT1024_WITH_RC4_56_SHA = "tls_rsa_rc4_56_sha";
    public static final String PR_TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA = "tls_rsa_des_sha";

    /*========================================================
     * Watchdog and Server State Messages
     *========================================================*/

    public static final String SERVER_STARTUP_WARNING_MESSAGE = "CMS Warning: ";
    public static final String SERVER_SHUTDOWN_MESSAGE = "Shutting down.";
    public static final String SERVER_SHUTDOWN_ERROR_MESSAGE = "Error Starting CMS: ";
    public static final String SERVER_SHUTDOWN_EXTENDED_ERROR_MESSAGE = "Extended error information: ";

    /*============================================================
     * THE FOLLOWING LIST WILL BE REMOVED
     *============================================================*/

    // parameter types
    public static final String PT_OP = "op";
    public static final String PT_MOD_TYPE = "modType";
    public static final String PT_MOD_OP = "modOp";
    public static final String MOD_REPLACE = "modOpReplace";
    public static final String MOD_ADD = "modOpAdd";
    public static final String MOD_DELETE = "modOpDelete";
    public static final String PT_MOD_VALUE = "modValue";

    // generic operations
    public static final String OP_SET = "set";
    public static final String OP_GET = "get";
    public static final String OP_LIST = "list";

    // certificate server operations
    public static final String CERTSRV_ID = "certsrv";

    public static final String PT_PORT = "http.http.port";
    public static final String PT_SSL_PORT = "http.https.port";
    public static final String PT_MAPPING = "mapping";
    public static final String PT_DN = "dn";

    public static final String PV_SYSTEM_ADMINISTRATORS =
            "SystemAdministrators";
    public static final String PV_CERTIFICATE_ADMINISTRATORS =
            "CertificateAdministrators";

    public static final String OP_AUTHENTICATE = "authenticate";
    public static final String OP_RESTART = "restart";
    public static final String OP_STOP = "stop";

    // access manager operation
    public static final String PT_ACLS = "acls";
    public static final String OP_GET_ACLS = "getACLs";

    // authentication operations
    public static final String AUTH_ID = "auth";
    public static final String OP_FIND_USERS = "findUsers";
    public static final String OP_FIND_GROUPS = "findGroups";
    public static final String OP_GET_USER = "getUser";
    public static final String OP_GET_GROUP = "getGroup";
    public static final String OP_ADD_USER = "addUser";
    public static final String OP_ADD_GROUP = "addGroup";
    public static final String OP_MODIFY_USER = "modifyUser";
    public static final String OP_MODIFY_GROUP = "modifyGroup";

    public static final String PT_USER = "user";
    public static final String PT_GROUP = "group";

    // common operations
    public static final String OP_LOCK_REQUEST = "lockRequest";
    public static final String OP_MODIFY_REQUEST = "modifyRequest";
    public static final String OP_EXECUTE_REQUEST = "executeRequest";
    public static final String OP_ACCEPT_REQUEST = "acceptRequest";
    public static final String OP_REJECT_REQUEST = "rejectRequest";
    public static final String OP_CANCEL_REQUEST = "cancelRequest";

    // certificate authority operations
    public static final String PT_PUBLISH_DN = "ldappublish.ldap.admin-dn";
    public static final String PT_PUBLISH_PWD =
            "ldappublish.ldap.admin-password";
    public static final String PT_PUBLISH_FREQ =
            "crl.crl0.autoUpdateInterval";
    public static final String PT_SERIALNO = "serialno";
    public static final String PT_NAMES = "names";
    public static final String PT_CERTIFICATES = "certificates";
    public static final String PT_CERT_RECORDS = "certRecords";
    public static final String PT_REQUESTS = "requests";
    public static final String PT_REQUEST = "request";
    public static final String PT_EXTENSIONS = "extensions";
    public static final String PT_FILTER = "filter";
    public static final String PT_ATTRS = "attrs";
    public static final String PT_RESULT_ID = "resultId";
    public static final String PT_START_NO = "startNo";
    public static final String PT_END_NO = "endNo";
    public static final String PT_SIZE = "size";
    public static final String PT_RELEASE = "release";
    public static final String PT_CERTREC = "certrec";
    public static final String PT_COMMENT = "comment";
    public static final String PT_REASON_NO = "reasonNo";

    public static final String OP_CRL_PUBLISH = "publish_now";
    public static final String OP_FIND_CERTIFICATES = "findCertificates";
    public static final String OP_FIND_CERT_RECORDS = "findCertRecords";
    public static final String OP_FIND_REQUESTS = "findRequests";
    public static final String OP_LOCK_CERT_RECORD = "lockCertRecord";
    public static final String OP_MODIFY_CERT_RECORD = "modifyCertRecord";
    public static final String OP_GET_EXTENSIONS = "getExtensions";
    public static final String OP_REVOKE_CERT = "revokeCert";
    public static final String OP_RENEW_CERT = "renewCert";
    public static final String OP_GET_CACERT_CHAIN = "getCACertChain";

    // escrow authority operations
    public static final String PT_OLD_PASSWORD = "oldpassword";
    public static final String PT_NEW_PASSWORD = "newpassword";
    public static final String PT_KEY_RECORD = "keyRecord";

    public static final String OP_FIND_KEY_RECORDS = "findKeyRecords";
    public static final String OP_LOCK_KEY_RECORD = "lockKeyRecord";
    public static final String OP_MODIFY_KEY_RECORD = "modifyKeyRecord";
    public static final String OP_RECOVER_KEY = "recoverKey";

    // centralized cetificate management operations
    public static final String PT_NOTIF_EMAIL = "notificationEmail";
    public static final String PT_NOTIF_ENABLE = "notificationEnable";
    public static final String PT_NOTIF_EXPIRE = "notificationExpiration";
    public static final String PT_NOTIF_RENEWAL = "notificationRewnewal";
    public static final String PT_DIST_STORE = "storeUserPassword";
    public static final String PT_DIST_EMAIL = "emailUserPassword";
    public static final String PT_REQUEST_LOG = "requestLog";
    public static final String PT_ACCESS_LOG = "accessLog";
    public static final String PT_ERROR_LOG = "errorLog";
    public static final String PR_NT_EVENT_SOURCE = "NTEventSourceName";
    public static final String PR_NT_LOG_LEVEL = "level";
    public static final String PR_NT_LOG_ENABLED = "on";

    public static final String OP_GET_ACCESS_LOG = "getAccessLog";
    public static final String OP_GET_ERROR_LOG = "getErrorLog";
    public static final String OP_GET_REQUEST_LOG = "getRequestLog";

    public static final String PR_NICK_NAME = "nickName"; // capital N
    public static final String PR_LOGGED_IN = "isLoggedIn";

    // User Type
    public static final String PR_USER_TYPE = "userType";
    public static final String PR_ADMIN_TYPE = "adminType";
    public static final String PR_AGENT_TYPE = "agentType";
    public static final String PR_SUBSYSTEM_TYPE = "subsystemType";

    // Extended plugin information
    public static final String PR_EXT_PLUGIN_IMPLNAME = "implName";
    public static final String PR_EXT_PLUGIN_IMPLTYPE = "implType";
    public static final String PR_EXT_PLUGIN_IMPLTYPE_POLICY = "policy";
    public static final String PR_EXT_PLUGIN_IMPLTYPE_JOBS = "jobs";
    public static final String PR_EXT_PLUGIN_IMPLTYPE_AUTH = "auth";
    public static final String PR_EXT_PLUGIN_IMPLTYPE_LISTENER = "listener";
    public static final String PR_EXT_PLUGIN_IMPLTYPE_PUBLISHRULE = "publishrule";
    public static final String PR_EXT_PLUGIN_IMPLTYPE_PUBLISHER = "publisher";
    public static final String PR_EXT_PLUGIN_IMPLTYPE_MAPPER = "mapperrule";
    public static final String PR_EXT_PLUGIN_IMPLTYPE_CRLEXTSRULE = "crlExtensions";
    public static final String PR_EXT_PLUGIN_IMPLTYPE_OCSPSTORESRULE = "ocspStores";

    // Miscellaneous
    public static final String PR_CERT_FILEPATH = "certFilePath";
    public static final String PR_SERVER_ROOT = "serverRoot";
    public static final String PR_SERVER_ID = "serverID";
    public static final String PR_NT = "NT";
    public static final String PR_TIMEOUT = "timeout";
    public static final String PR_ALL_NICKNAMES = "allNicknames";

    // request status
    public static final String PR_REQUEST_SUCCESS = "2";
    public static final String PR_REQUEST_PENDING = "3";
    public static final String PR_REQUEST_SVC_PENDING = "4";
    public static final String PR_REQUEST_REJECTED = "5";

    //Profile
    public static final String PR_CONSTRAINTS_LIST = "constraintPolicy";

    //Replication
    public static final String PR_REPLICATION_ENABLED = "replication.enabled";
    public static final String PR_REPLICATION_AGREEMENT_NAME_1 = "replication.master1.name";
    public static final String PR_REPLICATION_HOST_1 = "replication.master1.hostname";
    public static final String PR_REPLICATION_PORT_1 = "replication.master1.port";
    public static final String PR_REPLICATION_BINDDN_1 = "replication.master1.binddn";
    public static final String PR_REPLICATION_CHANGELOGDB_1 = "replication.master1.changelogdb";
    public static final String PR_REPLICATION_AGREEMENT_NAME_2 = "replication.master2.name";
    public static final String PR_REPLICATION_HOST_2 = "replication.master2.hostname";
    public static final String PR_REPLICATION_PORT_2 = "replication.master2.port";
    public static final String PR_REPLICATION_BINDDN_2 = "replication.master2.binddn";
    public static final String PR_REPLICATION_CHANGELOGDB_2 = "replication.master2.changelogdb";

    //Config
    public static final String CFG_ENABLED = "Enabled";
    public static final String CFG_DISABLED = "Disabled";
    public static final String CFG_PENDING_APPROVAL = "Pending_Approval";
}
