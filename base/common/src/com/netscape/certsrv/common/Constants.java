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
    public final static String TRUE = "true";
    public final static String FALSE = "false";
    public final static String VIEW = "view";
    public final static String EDIT = "edit";

    public final static String OP_TYPE = "OP_TYPE";
    public final static String OP_SCOPE = "OP_SCOPE";

    //STATIC RESOURCE IDENTIFIERS
    public final static String RS_ID = "RS_ID";
    public final static String RS_ID_CONFIG = "RS_ID_CONFIG";
    public final static String RS_ID_ORDER = "RS_ID_ORDER";

    //STATIC UI TYPE
    public final static String TYPE_PASSWORD = "password";

    /**********************************************************
     * PROPERTY NAME LISTED BELOW
     **********************************************************/

    /*========================================================
     * General
     *========================================================*/
    public final static String PR_PORT = "port";
    public final static String PR_SSLPORT = "sslPort";

    /*========================================================
     * Tasks
     *========================================================*/
    public final static String PR_SERVER_START = "start";
    public final static String PR_SERVER_STOP = "stop";
    public final static String PR_SERVER_RESTART = "restart";

    /*========================================================
     * Networks
     *========================================================*/
    public final static String PR_ADMIN_S_PORT = "admin.https.port";
    public final static String PR_AGENT_S_PORT = "agent.https.port";
    public final static String PR_GATEWAY_S_PORT = "gateway.https.port";
    public final static String PR_GATEWAY_PORT = "gateway.http.port";
    public final static String PR_DOC_ROOT = "docroot";
    public final static String PR_ADMIN_S_BACKLOG = "admin.https.backlog";
    public final static String PR_AGENT_S_BACKLOG = "agent.https.backlog";
    public final static String PR_GATEWAY_S_BACKLOG = "gateway.https.backlog";
    public final static String PR_GATEWAY_BACKLOG = "gateway.http.backlog";
    public final static String PR_GATEWAY_PORT_ENABLED =
            "gateway.http.enable";
    public final static String PR_MASTER_AGENT_PORT = "master.ca.agent.port";
    public final static String PR_MASTER_AGENT_HOST = "master.ca.agent.host";

    /*========================================================
     * SMTP
     *========================================================*/
    public final static String PR_SERVER_NAME = "server";

    /*========================================================
     * SNMP
     *========================================================*/
    public final static String PR_SNMP_ENABLED = "on";
    public final static String PR_SNMP_MASTER_HOST = "master.host";
    public final static String PR_SNMP_MASTER_PORT = "master.port";
    public final static String PR_SNMP_DESC = "desc";
    public final static String PR_SNMP_ORGN = "orgn";
    public final static String PR_SNMP_LOC = "loc";
    public final static String PR_SNMP_CONTACT = "contact";

    /*========================================================
     * Self Tests
     *========================================================*/
    public final static String PR_RUN_SELFTESTS_ON_DEMAND = "run";
    public final static String PR_RUN_SELFTESTS_ON_DEMAND_CLASS = "class";
    public final static String PR_RUN_SELFTESTS_ON_DEMAND_CONTENT = "runContent";

    /*========================================================
     * Users and Groups
     *========================================================*/

    //group properties
    public final static String PR_GROUP_DESC = "desc";
    public final static String PR_GROUP_USER = "user";
    public final static String PR_GROUP_GROUP = "group";

    //user properties
    public final static String PR_USER_FULLNAME = "fullname";
    public final static String PR_USER_PASSWORD = "password";
    public final static String PR_USER_EMAIL = "email";
    public final static String PR_USER_PHONE = "phone";
    public final static String PR_USER_STATE = "state";
    public final static String PR_USER_CERT = "cert";
    public final static String PR_USER_GROUP = "groups";
    public final static String PR_MULTIROLES = "multiroles";

    /*========================================================
     * Authentication
     *========================================================*/
    public final static String PR_PING = "ping";
    public final static String PR_AUTH_CLASS = "class";
    public final static String PR_AUTH_IMPL_NAME = "implName";
    public final static String PR_AUTH_HOST = "ldapconn.host";
    public final static String PR_AUTH_PORT = "ldapconn.port";
    public final static String PR_AUTH_BASEDN = "basedn";
    public final static String PR_AUTH_ADMIN_DN = "ldapauth.bindDN";
    public final static String PR_AUTH_ADMIN_PWD = "ldapauth.bindPassword";

    /*========================================================
     * Job Scheduler
     *========================================================*/
    public final static String PR_JOBS_CLASS = "class";
    public final static String PR_JOBS_IMPL_NAME = "implName";
    public final static String PR_JOBS_FREQUENCY = "frequency";

    /*========================================================
     * Notification
     *========================================================*/
    public final static String PR_NOTIFICATION_FORM_NAME = "emailTemplate";
    public final static String PR_NOTIFICATION_SUBJECT =
            "emailSubject";
    public final static String PR_NOTIFICATION_SENDER = "senderEmail";
    public final static String PR_NOTIFICATION_RECEIVER = "recipientEmail";

    /*========================================================
     * Logs
     *========================================================*/
    public static final String PR_LOG_IMPL_NAME = "implName";
    public static final String PR_EXT_PLUGIN_IMPLTYPE_LOG = "log";
    public final static String PR_LOG_CLASS = "class";
    public final static String PR_LOG_INSTANCE = "instanceName";
    public final static String PR_LOG_ONE = "entry";
    public final static String PR_LOG_ENTRY = "maxentry";
    public final static String PR_LOG_SOURCE = "source";
    public final static String PR_LOG_LEVEL = "level";
    public final static String PR_LOG_ENABLED = "on";
    public final static String PR_LOG_BUFFERSIZE = "bufferSize";
    public final static String PR_LOG_EXPIRED_TIME = "expirationTime";
    public final static String PR_LOG_FILENAME = "fileName";
    public final static String PR_LOG_FLUSHINTERVAL = "flushInterval";
    public final static String PR_LOG_MAXFILESIZE = "maxFileSize";
    public final static String PR_LOG_ROLLEROVER_INTERVAL = "rolloverInterval";
    public final static String PR_LOG_TYPE = "type";
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

    public static final String PR_DEBUG_LOG_SHOWCALLER = "debug.showcaller";
    public static final String PR_DEBUG_LOG_ENABLE = "debug.enabled";
    public static final String PR_DEBUG_LOG_LEVEL = "debug.level";

    /*========================================================
     * LDAP Publishing
     *========================================================*/

    // publishing properties
    public final static String PR_BASIC_AUTH = "BasicAuth";
    public final static String PR_SSL_AUTH = "SslClientAuth";
    public final static String PR_AUTH_TYPE = "ldapauth.authtype";
    public final static String PR_BINDPWD_PROMPT = "ldapauth.bindPWPrompt";
    public final static String PR_CERT_NAMES = "ldapauth.nicknames";
    public final static String PR_LDAP_CLIENT_CERT = "ldapauth.clientCertNickname";
    public final static String PR_DIRECTORY_MANAGER_PWD = "directoryManagerPwd";

    // crl settings
    public final static String PR_ENABLE_CRL = "enableCRLUpdates";
    public final static String PR_UPDATE_SCHEMA = "updateSchema";
    public final static String PR_EXTENDED_NEXT_UPDATE = "extendedNextUpdate";
    public final static String PR_UPDATE_ALWAYS = "alwaysUpdate";
    public final static String PR_ENABLE_DAILY = "enableDailyUpdates";
    public final static String PR_DAILY_UPDATES = "dailyUpdates";
    public final static String PR_ENABLE_FREQ = "enableUpdateInterval";
    public final static String PR_UPDATE_FREQ = "autoUpdateInterval";
    public final static String PR_GRACE_PERIOD = "nextUpdateGracePeriod";
    public final static String PR_NEXT_AS_THIS_EXTENSION = "nextAsThisUpdateExtension";
    public final static String PR_ENABLE_CACHE = "enableCRLCache";
    public final static String PR_CACHE_FREQ = "cacheUpdateInterval";
    public final static String PR_CACHE_RECOVERY = "enableCacheRecovery";
    public final static String PR_CACHE_TESTING = "enableCacheTesting";
    public final static String PR_EXTENSIONS = "allowExtensions";
    public final static String PR_INCLUDE_EXPIREDCERTS = "includeExpiredCerts";
    public final static String PR_INCLUDE_EXPIREDCERTS_ONEEXTRATIME = "includeExpiredCertsOneExtraTime";
    public final static String PR_CA_CERTS_ONLY = "caCertsOnly";
    public final static String PR_PROFILE_CERTS_ONLY = "profileCertsOnly";
    public final static String PR_PROFILE_LIST = "profileList";
    public final static String PR_SIGNING_ALGORITHM = "signingAlgorithm";
    public final static String PR_MD2_RSA = "MD2withRSA";
    public final static String PR_MD5_RSA = "MD5withRSA";
    public final static String PR_SHA1_RSA = "SHA1withRSA";
    public final static String PR_SHA1_DSA = "SHA1withDSA";
    public final static String PR_DESCRIPTION = "description";
    public final static String PR_CLASS = "class";

    // ldap settings
    public final static String PR_ENABLE = "enable";
    public final static String PR_PUBLISHING_ENABLE = "publishingEnable";
    public final static String PR_HOST_NAME = "ldapconn.host";
    public final static String PR_SECURE_PORT_ENABLED = "ldapconn.secureConn";
    public final static String PR_LDAP_PORT = "ldapconn.port";
    public final static String PR_LDAP_VERSION = "ldapconn.version";
    public final static String PR_BIND_DN = "ldapauth.bindDN";
    public final static String PR_BIND_PASSWD = "ldapauth.bindPassword";
    public final static String PR_BIND_PASSWD_AGAIN = "bindPasswdAgain";
    public final static String PR_LDAP_MAX_CONNS = "maxConns";
    public final static String PR_LDAP_MIN_CONNS = "minConns";
    public final static String PR_PUBLISHING_QUEUE_ENABLE = "queue.enable";
    public final static String PR_PUBLISHING_QUEUE_THREADS = "queue.maxNumberOfThreads";
    public final static String PR_PUBLISHING_QUEUE_PAGE_SIZE = "queue.pageSize";
    public final static String PR_PUBLISHING_QUEUE_PRIORITY = "queue.priorityLevel";
    public final static String PR_PUBLISHING_QUEUE_STATUS = "queue.saveStatus";

    public final static String PR_BASE_DN = "baseDN";
    public final static String PR_DNCOMPS = "dnComps";
    public final static String PR_FILTERCOMPS = "filterComps";

    // ldap connection test
    public final static String PR_CONN_INITED = "connInited";
    public final static String PR_CONN_INIT_FAIL = "connInitFail";
    public final static String PR_CONN_OK = "connOk";
    public final static String PR_CONN_FAIL = "connFail";
    public final static String PR_AUTH_OK = "authOk";
    public final static String PR_AUTH_FAIL = "authFail";
    public final static String PR_SAVE_OK = "saveOk";
    public final static String PR_SAVE_NOT = "saveOrNot";

    /*========================================================
     * Plugin
     *========================================================*/
    public final static String PR_PLUGIN_IMP = "imp";
    public final static String PR_PLUGIN_INSTANCE = "instance";

    /*========================================================
     * Policy
     *========================================================*/
    public final static String PR_POLICY_CLASS = "class";
    public final static String PR_POLICY_IMPL_NAME = "implName";
    public final static String PR_CRLDP_NAME = "crldpName";
    public final static String PR_POLICY_DESC = "desc";
    public final static String PR_POLICY_ORDER = "order";
    public final static String PR_POLICY_ENABLE = "enable";
    public final static String PR_POLICY_PREDICATE = "predicate";

    /*========================================================
     * Publish
     *========================================================*/
    public final static String PR_PUBLISHER = "publisher";
    public final static String PR_PUBLISHER_CLASS = "class";
    public final static String PR_PUBLISHER_IMPL_NAME = "implName";
    public final static String PR_PUBLISHER_DESC = "desc";
    public final static String PR_PUBLISHER_ORDER = "order";
    public final static String PR_PUBLISHER_ENABLE = "enable";

    public final static String PR_MAPPER = "mapper";
    public final static String PR_MAPPER_CLASS = "class";
    public final static String PR_MAPPER_IMPL_NAME = "implName";
    public final static String PR_MAPPER_DESC = "desc";
    public final static String PR_MAPPER_ORDER = "order";
    public final static String PR_MAPPER_ENABLE = "enable";

    public final static String PR_RULE = "rule";
    public final static String PR_RULE_CLASS = "class";
    public final static String PR_RULE_IMPL_NAME = "implName";
    public final static String PR_RULE_DESC = "desc";
    public final static String PR_RULE_ORDER = "order";
    public final static String PR_RULE_ENABLE = "enable";

    public final static String PR_CRLEXT = "crlExt";
    public final static String PR_CRLEXT_CLASS = "class";
    public final static String PR_CRLEXT_IMPL_NAME = "implName";
    public final static String PR_CRLEXT_DESC = "desc";
    public final static String PR_CRLEXT_ORDER = "order";
    public final static String PR_CRLEXT_ENABLE = "enable";

    public final static String PR_OCSPSTORE_IMPL_NAME = "implName";

    /*========================================================
     * Registration Authority
     *========================================================*/
    public final static String PR_EE_ENABLED = "eeEnabled";
    public final static String PR_OCSP_ENABLED = "ocspEnabled";
    public final static String PR_RA_ENABLED = "raEnabled";
    public final static String PR_RENEWAL_ENABLED = "renewal.enabled";
    public final static String PR_RENEWAL_VALIDITY = "renewal.validity";
    public final static String PR_RENEWAL_EMAIL = "renewal.email";
    public final static String PR_RENEWAL_EXPIREDNOTIFIEDENABLED =
            "renewal.expired.notification.enabled";
    public final static String PR_RENEWAL_NUMNOTIFICATION =
            "renewal.numNotification";
    public final static String PR_RENEWAL_INTERVAL = "renewal.interval";
    public final static String PR_SERVLET_CLASS = "class";
    public final static String PR_SERVLET_URI = "uri";
    public final static String PR_IMPL_NAME = "implName";
    public final static String PR_LOCAL = "local";
    public final static String PR_ID = "id";
    public final static String PR_HOST = "host";
    public final static String PR_URI = "uri";
    public final static String PR_ENABLED = "enable";

    /*========================================================
     * Certificate Authority
     *========================================================*/
    public final static String PR_VALIDITY = "validity";
    public final static String PR_DEFAULT_ALGORITHM = "defaultSigningAlgorithm";
    public final static String PR_ALL_ALGORITHMS = "allSigningAlgorithms";
    public final static String PR_SERIAL = "startSerialNumber";
    public final static String PR_MAXSERIAL = "maxSerialNumber";
    public final static String PR_SN_MANAGEMENT = "serialNumberManagement";
    public final static String PR_RANDOM_SN = "randomSerialNumbers";

    /*========================================================
     * Access Control
     *========================================================*/
    public final static String PR_ACL_OPS = "aclOperations";
    public final static String PR_ACI = "aci";
    public final static String PR_ACL_CLASS = "class";
    public final static String PR_ACL_DESC = "desc";
    public final static String PR_ACL_RIGHTS = "rights";

    /*========================================================
     * Key Recovery
     *========================================================*/
    public final static String PR_AUTO_RECOVERY_ON = "autoRecoveryOn";
    public final static String PR_RECOVERY_N = "recoveryN";
    public final static String PR_RECOVERY_M = "recoveryM";
    public final static String PR_OLD_RECOVERY_AGENT = "oldRecoveryAgent";
    public final static String PR_RECOVERY_AGENT = "recoveryAgent";
    public final static String PR_OLD_AGENT_PWD = "oldAgentPwd";
    public final static String PR_AGENT_PWD = "agentPwd";
    public final static String PR_NO_OF_REQUIRED_RECOVERY_AGENTS = "noOfRequiredRecoveryAgents";

    /*========================================================
     * Status
     *========================================================*/
    public final static String PR_STAT_STARTUP = "startup";
    public final static String PR_STAT_TIME = "time";
    public final static String PR_STAT_VERSION = "cms.version";
    public final static String PR_STAT_INSTALLDATE = "installDate";
    public final static String PR_STAT_INSTANCEID = "instanceId";

    /*========================================================
     * Server Instance
     *========================================================*/
    public final static String PR_INSTALL = "install";
    public final static String PR_INSTANCES_INSTALL = "instancesInstall";
    public final static String PR_CA_INSTANCE = "ca";
    public final static String PR_OCSP_INSTANCE = "ocsp";
    public final static String PR_RA_INSTANCE = "ra";
    public final static String PR_KRA_INSTANCE = "kra";
    public final static String PR_TKS_INSTANCE = "tks";

    /*
     * Certificate info
     */
    public final static String PR_CA_SIGNING_NICKNAME = "caSigningCert";
    public final static String PR_PKCS10 = "pkcs10";
    public final static String PR_CERT_SUBJECT_NAME = "certSubjectName";
    public final static String PR_ISSUER_NAME = "issuerName";
    public final static String PR_SERIAL_NUMBER = "serialNumber";
    public final static String PR_BEFORE_VALIDDATE = "beforeValidDate";
    public final static String PR_AFTER_VALIDDATE = "afterValidDate";
    public final static String PR_CERT_FINGERPRINT = "certFingerPrint";
    public final static String PR_SIGNATURE_ALGORITHM = "signatureAlg";
    public final static String PR_ALGORITHM_ID = "algorithmId";
    public final static String PR_NICKNAME = "nickname";
    public final static String PR_ADD_CERT = "addCert";
    public final static String PR_CERT_CONTENT = "certContent";

    /*
     * Certificate type
     */
    public final static String PR_CERTIFICATE_TYPE = "certType";
    public final static String PR_CERTIFICATE_SUBTYPE = "certSubType";
    public final static String PR_CA_SIGNING_CERT = "caSigningCert";
    public final static String PR_RA_SIGNING_CERT = "raSigningCert";
    public final static String PR_OCSP_SIGNING_CERT = "ocspSigningCert";
    public final static String PR_KRA_TRANSPORT_CERT = "kraTransportCert";
    public final static String PR_SERVER_CERT = "serverCert";
    public final static String PR_SUBSYSTEM_CERT = "subsystemCert";
    public final static String PR_SERVER_CERT_RADM = "serverCertRadm";
    public final static String PR_CROSS_CERT = "crossCert";
    public final static String PR_OTHER_CERT = "otherCert";
    public final static String PR_SERVER_CERT_CHAIN = "serverCertChain";
    public final static String PR_TRUSTED_CA_CERT = "trustedCACert";
    public final static String PR_TRUSTED_CERT = "trustedCert";
    public final static String PR_AUDIT_SIGNING_CERT = "auditSigningCert";

    /*
     * Extensions
     */
    public final static String PR_VALIDITY_PERIOD = "validityPeriod";
    public final static String PR_BEGIN_YEAR = "beginYear";
    public final static String PR_BEGIN_MONTH = "beginMonth";
    public final static String PR_BEGIN_DATE = "beginDate";
    public final static String PR_BEGIN_HOUR = "beginHour";
    public final static String PR_BEGIN_MIN = "beginMin";
    public final static String PR_BEGIN_SEC = "beginSec";
    public final static String PR_AFTER_YEAR = "afterYear";
    public final static String PR_AFTER_MONTH = "afterMonth";
    public final static String PR_AFTER_DATE = "afterDate";
    public final static String PR_AFTER_HOUR = "afterHour";
    public final static String PR_AFTER_MIN = "afterMin";
    public final static String PR_AFTER_SEC = "afterSec";
    public final static String PR_AIA = "aia";
    public final static String PR_AKI = "aki";
    public final static String PR_OCSP_SIGNING = "ocspSigning";
    public final static String PR_OCSP_NOCHECK = "ocspNoCheck";
    public final static String PR_SKI = "ski";
    public final static String PR_KEY_USAGE = "keyUsage";
    public final static String PR_DER_EXTENSION = "derExtension";
    public final static String PR_IS_CA = "isCA";
    public final static String PR_CERT_LEN = "certLen";
    public final static String PR_SSL_CLIENT_BIT = "sslClientBit";
    public final static String PR_SSL_SERVER_BIT = "sslServerBit";
    public final static String PR_SSL_MAIL_BIT = "sslMailBit";
    public final static String PR_SSL_CA_BIT = "sslCABit";
    public final static String PR_OBJECT_SIGNING_BIT = "objectSigningBit";
    public final static String PR_MAIL_CA_BIT = "mailCABit";
    public final static String PR_OBJECT_SIGNING_CA_BIT = "objectSigningCABit";
    public final static String PR_TIMESTAMPING_BIT = "timeStampingBit";
    public final static String PR_CA_KEYID = "caKeyid";
    public final static String PR_CA_KEYPAIR = "caKeyPair";

    /**
     * Trust database
     */
    public final static String PR_TRUST = "trust";

    /*========================================================
     * Security
     *========================================================*/

    //functionality
    public final static String PR_CERT_SERVER = "SERVER";
    public final static String PR_CERT_ADMIN = "ADMIN";
    public final static String PR_CERT_AGENT = "AGENT";
    public final static String PR_CERT_EE = "EE";
    public final static String PR_CERT_CA = "CA";
    public final static String PR_CERT_RA = "RA";
    public final static String PR_CERT_POA = "POA";
    public final static String PR_CERT_TRANS = "TRANS";

    // key and certificate management
    public final static String PR_OPERATION_TYPE = "operationtype";
    public final static String PR_INSTALL_TYPE = "install";
    public final static String PR_REQUEST_TYPE = "request";
    //public final static String PR_CA_SIGNING_CERT = "cacert";
    //public final static String PR_SERVER_CERT = "servercert";
    public final static String PR_CLIENT_CERT = "clientcert";
    public final static String PR_FULL_INTERNAL_TOKEN_NAME = "Internal Key Storage Token";
    public final static String PR_INTERNAL_TOKEN_NAME =
            "internal";
    public final static String PR_TOKEN_NAME = "tokenName";
    public final static String PR_TOKEN_PASSWD = "tokenPwd";
    public final static String PR_KEY_LENGTH = "keyLength";
    public final static String PR_KEY_CURVENAME = "keyCurveName";
    public static final String PR_SIGNEDBY_TYPE = "signedBy";
    public final static String PR_KEY_TYPE = "keyType";
    public final static String PR_PQGPARAMS = "pqgParams";
    public final static String PR_CERT_REQUEST = "certReq";
    public final static String PR_CERT_REQUEST_DIR = "certReqDir";
    public final static String PR_CERT_CONFIG_DIR = "certConfigDir";
    public final static String PR_IMPORT_CERT = "importCert";
    public final static String PR_SUBJECT_NAME = "subjectName";
    public final static String PR_CSR = "csr";

    //encryption

    /* Cipher Version: domestic or export */
    public final static String PR_CIPHER_VERSION = "cipherversion";
    public final static String PR_CIPHER_VERSION_DOMESTIC = "cipherdomestic";
    public final static String PR_CIPHER_VERSION_EXPORT = "cipherexport";

    /* Cipher Fortezza: true, false */
    public final static String PR_CIPHER_FORTEZZA = "cipherfortezza";

    /* Token and Certificates */
    public final static String PR_TOKEN_LIST = "tokenlist";
    public final static String PR_TOKEN_PREFIX = "token_";
    public final static String PR_INTERNAL_TOKEN = "internal";
    public final static String PR_KEY_LIST = "keylist";

    /* SSL Cipher Preferences */
    public final static String PR_CIPHER_PREF = "cipherpref";

    /* SSL EC Type */
    public final static String PR_ECTYPE = "ectype";

    /* values for SSL cipher preferences */
    public final static String PR_SSL2_RC4_128_WITH_MD5 = "rc4";
    public final static String PR_SSL2_RC4_128_EXPORT40_WITH_MD5 = "rc4export";
    public final static String PR_SSL2_RC2_128_CBC_WITH_MD5 = "rc2";
    public final static String PR_SSL2_RC2_128_CBC_EXPORT40_WITH_MD5 = "rc2export";
    public final static String PR_SSL2_DES_64_CBC_WITH_MD5 = "des";
    public final static String PR_SSL2_DES_192_EDE3_CBC_WITH_MD5 = "desede3";
    public final static String PR_SSL3_RSA_WITH_NULL_MD5 = "rsa_null_md5";
    public final static String PR_SSL3_RSA_EXPORT_WITH_RC4_40_MD5 = "rsa_rc4_40_md5";
    public final static String PR_SSL3_RSA_WITH_RC4_128_MD5 = "rsa_rc4_128_md5";
    public final static String PR_SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = "rsa_rc2_40_md5";
    public final static String PR_SSL3_RSA_WITH_DES_CBC_SHA = "rsa_des_sha";
    public final static String PR_SSL3_RSA_WITH_3DES_EDE_CBC_SHA = "rsa_3des_sha";
    public final static String PR_SSL3_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA = "fortezza";
    public final static String PR_SSL3_FORTEZZA_DMS_WITH_RC4_128_SHA = "fortezza_rc4_128_sha";
    public final static String PR_SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA = "rsa_fips_3des_sha";
    public final static String PR_SSL_RSA_FIPS_WITH_DES_CBC_SHA = "rsa_fips_des_sha";
    public final static String PR_TLS_RSA_EXPORT1024_WITH_RC4_56_SHA = "tls_rsa_rc4_56_sha";
    public final static String PR_TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA = "tls_rsa_des_sha";

    /*========================================================
     * Watchdog and Server State Messages
     *========================================================*/

    public final static String SERVER_STARTUP_WARNING_MESSAGE = "CMS Warning: ";
    public final static String SERVER_STARTUP_MESSAGE = "Server is started.";
    public final static String SERVER_SHUTDOWN_MESSAGE = "Shutting down.";
    public final static String SERVER_SHUTDOWN_ERROR_MESSAGE = "Error Starting CMS: ";
    public final static String SERVER_SHUTDOWN_EXTENDED_ERROR_MESSAGE = "Extended error information: ";

    /*============================================================
     * THE FOLLOWING LIST WILL BE REMOVED
     *============================================================*/

    // parameter types
    public final static String PT_OP = "op";
    public final static String PT_MOD_TYPE = "modType";
    public final static String PT_MOD_OP = "modOp";
    public final static String MOD_REPLACE = "modOpReplace";
    public final static String MOD_ADD = "modOpAdd";
    public final static String MOD_DELETE = "modOpDelete";
    public final static String PT_MOD_VALUE = "modValue";

    // generic operations
    public final static String OP_SET = "set";
    public final static String OP_GET = "get";
    public final static String OP_LIST = "list";

    // certificate server operations
    public final static String CERTSRV_ID = "certsrv";

    public final static String PT_PORT = "http.http.port";
    public final static String PT_SSL_PORT = "http.https.port";
    public final static String PT_MAPPING = "mapping";
    public final static String PT_DN = "dn";

    public final static String PV_SYSTEM_ADMINISTRATORS =
            "SystemAdministrators";
    public final static String PV_CERTIFICATE_ADMINISTRATORS =
            "CertificateAdministrators";

    public final static String OP_AUTHENTICATE = "authenticate";
    public final static String OP_RESTART = "restart";
    public final static String OP_STOP = "stop";

    // access manager operation
    public final static String PT_ACLS = "acls";
    public final static String OP_GET_ACLS = "getACLs";

    // authentication operations
    public final static String AUTH_ID = "auth";
    public final static String OP_FIND_USERS = "findUsers";
    public final static String OP_FIND_GROUPS = "findGroups";
    public final static String OP_GET_USER = "getUser";
    public final static String OP_GET_GROUP = "getGroup";
    public final static String OP_ADD_USER = "addUser";
    public final static String OP_ADD_GROUP = "addGroup";
    public final static String OP_MODIFY_USER = "modifyUser";
    public final static String OP_MODIFY_GROUP = "modifyGroup";

    public final static String PT_USER = "user";
    public final static String PT_GROUP = "group";

    // common operations
    public final static String OP_LOCK_REQUEST = "lockRequest";
    public final static String OP_MODIFY_REQUEST = "modifyRequest";
    public final static String OP_EXECUTE_REQUEST = "executeRequest";
    public final static String OP_ACCEPT_REQUEST = "acceptRequest";
    public final static String OP_REJECT_REQUEST = "rejectRequest";
    public final static String OP_CANCEL_REQUEST = "cancelRequest";

    // certificate authority operations
    public final static String PT_PUBLISH_DN = "ldappublish.ldap.admin-dn";
    public final static String PT_PUBLISH_PWD =
            "ldappublish.ldap.admin-password";
    public final static String PT_PUBLISH_FREQ =
            "crl.crl0.autoUpdateInterval";
    public final static String PT_SERIALNO = "serialno";
    public final static String PT_NAMES = "names";
    public final static String PT_CERTIFICATES = "certificates";
    public final static String PT_CERT_RECORDS = "certRecords";
    public final static String PT_REQUESTS = "requests";
    public final static String PT_REQUEST = "request";
    public final static String PT_EXTENSIONS = "extensions";
    public final static String PT_FILTER = "filter";
    public final static String PT_ATTRS = "attrs";
    public final static String PT_RESULT_ID = "resultId";
    public final static String PT_START_NO = "startNo";
    public final static String PT_END_NO = "endNo";
    public final static String PT_SIZE = "size";
    public final static String PT_RELEASE = "release";
    public final static String PT_CERTREC = "certrec";
    public final static String PT_COMMENT = "comment";
    public final static String PT_REASON_NO = "reasonNo";

    public final static String OP_CRL_PUBLISH = "publish_now";
    public final static String OP_FIND_CERTIFICATES = "findCertificates";
    public final static String OP_FIND_CERT_RECORDS = "findCertRecords";
    public final static String OP_FIND_REQUESTS = "findRequests";
    public final static String OP_LOCK_CERT_RECORD = "lockCertRecord";
    public final static String OP_MODIFY_CERT_RECORD = "modifyCertRecord";
    public final static String OP_GET_EXTENSIONS = "getExtensions";
    public final static String OP_REVOKE_CERT = "revokeCert";
    public final static String OP_RENEW_CERT = "renewCert";
    public final static String OP_GET_CACERT_CHAIN = "getCACertChain";

    // escrow authority operations
    public final static String PT_OLD_PASSWORD = "oldpassword";
    public final static String PT_NEW_PASSWORD = "newpassword";
    public final static String PT_KEY_RECORD = "keyRecord";

    public final static String OP_FIND_KEY_RECORDS = "findKeyRecords";
    public final static String OP_LOCK_KEY_RECORD = "lockKeyRecord";
    public final static String OP_MODIFY_KEY_RECORD = "modifyKeyRecord";
    public final static String OP_RECOVER_KEY = "recoverKey";

    // centralized cetificate management operations
    public final static String PT_NOTIF_EMAIL = "notificationEmail";
    public final static String PT_NOTIF_ENABLE = "notificationEnable";
    public final static String PT_NOTIF_EXPIRE = "notificationExpiration";
    public final static String PT_NOTIF_RENEWAL = "notificationRewnewal";
    public final static String PT_DIST_STORE = "storeUserPassword";
    public final static String PT_DIST_EMAIL = "emailUserPassword";
    public final static String PT_REQUEST_LOG = "requestLog";
    public final static String PT_ACCESS_LOG = "accessLog";
    public final static String PT_ERROR_LOG = "errorLog";
    public final static String PR_NT_EVENT_SOURCE = "NTEventSourceName";
    public final static String PR_NT_LOG_LEVEL = "level";
    public final static String PR_NT_LOG_ENABLED = "on";

    public final static String OP_GET_ACCESS_LOG = "getAccessLog";
    public final static String OP_GET_ERROR_LOG = "getErrorLog";
    public final static String OP_GET_REQUEST_LOG = "getRequestLog";

    public final static String PR_NICK_NAME = "nickName"; // capital N
    public final static String PR_LOGGED_IN = "isLoggedIn";

    // User Type
    public final static String PR_USER_TYPE = "userType";
    public final static String PR_ADMIN_TYPE = "adminType";
    public final static String PR_AGENT_TYPE = "agentType";
    public final static String PR_SUBSYSTEM_TYPE = "subsystemType";

    // Extended plugin information
    public final static String PR_EXT_PLUGIN_IMPLNAME = "implName";
    public final static String PR_EXT_PLUGIN_IMPLTYPE = "implType";
    public final static String PR_EXT_PLUGIN_IMPLTYPE_POLICY = "policy";
    public final static String PR_EXT_PLUGIN_IMPLTYPE_JOBS = "jobs";
    public final static String PR_EXT_PLUGIN_IMPLTYPE_AUTH = "auth";
    public final static String PR_EXT_PLUGIN_IMPLTYPE_LISTENER = "listener";
    public final static String PR_EXT_PLUGIN_IMPLTYPE_PUBLISHRULE = "publishrule";
    public final static String PR_EXT_PLUGIN_IMPLTYPE_PUBLISHER = "publisher";
    public final static String PR_EXT_PLUGIN_IMPLTYPE_MAPPER = "mapperrule";
    public final static String PR_EXT_PLUGIN_IMPLTYPE_CRLEXTSRULE = "crlExtensions";
    public final static String PR_EXT_PLUGIN_IMPLTYPE_OCSPSTORESRULE = "ocspStores";

    // Miscellaneous
    public final static String PR_CERT_FILEPATH = "certFilePath";
    public final static String PR_SERVER_ROOT = "serverRoot";
    public final static String PR_SERVER_ID = "serverID";
    public final static String PR_NT = "NT";
    public final static String PR_TIMEOUT = "timeout";
    public final static String PR_ALL_NICKNAMES = "allNicknames";

    // request status
    public final static String PR_REQUEST_SUCCESS = "2";
    public final static String PR_REQUEST_PENDING = "3";
    public final static String PR_REQUEST_SVC_PENDING = "4";
    public final static String PR_REQUEST_REJECTED = "5";

    //Profile
    public final static String PR_CONSTRAINTS_LIST = "constraintPolicy";

    //Replication
    public final static String PR_REPLICATION_ENABLED = "replication.enabled";
    public final static String PR_REPLICATION_AGREEMENT_NAME_1 = "replication.master1.name";
    public final static String PR_REPLICATION_HOST_1 = "replication.master1.hostname";
    public final static String PR_REPLICATION_PORT_1 = "replication.master1.port";
    public final static String PR_REPLICATION_BINDDN_1 = "replication.master1.binddn";
    public final static String PR_REPLICATION_CHANGELOGDB_1 = "replication.master1.changelogdb";
    public final static String PR_REPLICATION_AGREEMENT_NAME_2 = "replication.master2.name";
    public final static String PR_REPLICATION_HOST_2 = "replication.master2.hostname";
    public final static String PR_REPLICATION_PORT_2 = "replication.master2.port";
    public final static String PR_REPLICATION_BINDDN_2 = "replication.master2.binddn";
    public final static String PR_REPLICATION_CHANGELOGDB_2 = "replication.master2.changelogdb";
}
