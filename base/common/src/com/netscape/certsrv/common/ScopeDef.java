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
 * This interface defines all the operation scope
 * used in the administration protocol between the
 * console and the server.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public interface ScopeDef {

    // users and groups
    public final static String SC_GROUPS = "groups";
    public final static String SC_GROUP_MEMBERS = "members";
    public final static String SC_USERS = "users";
    public final static String SC_USER_CERTS = "certs";

    public final static String SC_SNMP = "snmp";
    public final static String SC_SMTP = "smtp";
    public final static String SC_SUBSYSTEM = "subsystem";
    public final static String SC_ENCRYPTION = "encryption";
    public final static String SC_GATEWAY = "gateway";
    public final static String SC_ADMIN = "admin";
    public final static String SC_NETWORK = "network";

    // profile
    public final static String SC_PROFILE_IMPLS = "profile";
    public final static String SC_PROFILE_RULES = "rules";
    public final static String SC_PROFILE_DEFAULT_POLICY = "defaultPolicy";
    public final static String SC_PROFILE_CONSTRAINT_POLICY = "constraintPolicy";
    public final static String SC_PROFILE_POLICIES = "policies";
    public final static String SC_PROFILE_POLICY_CONFIG = "config";
    public final static String SC_PROFILE_INPUT = "profileInput";
    public final static String SC_PROFILE_INPUT_CONFIG = "profileInputConfig";
    public final static String SC_PROFILE_OUTPUT = "profileOutput";
    public final static String SC_PROFILE_OUTPUT_CONFIG = "profileOutputConfig";

    // policy management
    public final static String SC_POLICY_RULES = "rules";
    public final static String SC_POLICY_IMPLS = "impls";
    public final static String SC_POLICY_CRLDPS = "crldps";

    // publisher management
    public final static String SC_PUBLISHER_RULES = "publisherRules";
    public final static String SC_PUBLISHER_IMPLS = "publisherImpls";
    public final static String SC_MAPPER_RULES = "mapperRules";
    public final static String SC_MAPPER_IMPLS = "mapperImpls";
    public final static String SC_RULE_RULES = "ruleRules";
    public final static String SC_RULE_IMPLS = "ruleImpls";

    // self tests
    public final static String SC_SELFTESTS = "selftests";

    // log config
    public final static String SC_AUDITLOG = "transactionsLog";
    public final static String SC_NTAUDITLOG = "ntTransactionsLog";
    public final static String SC_ERRORLOG = "errorLog";
    public final static String SC_SYSTEMLOG = "systemLog";
    public final static String SC_NTSYSTEMLOG = "ntSystemLog";
    public final static String SC_LOG_ARCH = "logArch";
    public final static String SC_LOG_RULES = "logRule";
    public final static String SC_LOG_IMPLS = "logImpls";

    // log contents
    public final static String SC_LOG_INSTANCES = "log_instances";
    public final static String SC_LOG_CONTENT = "log_content";
    public final static String SC_AUDITLOG_CONTENT = "transactionsLog_content";
    public final static String SC_ERRORLOG_CONTENT = "errorLog_content";
    public final static String SC_SYSTEMLOG_CONTENT = "systemLog_content";

    //LDAP publishing
    public final static String SC_LDAP = "ldap";
    public final static String SC_CRL = "crl";
    public final static String SC_USERCERT = "userCert";
    public final static String SC_CACERT = "caCert";
    public final static String SC_CAMAPPER = "caMapper";
    public final static String SC_CAPUBLISHER = "caPublisher";
    public final static String SC_USERMAPPER = "userMapper";
    public final static String SC_USERPUBLISHER = "userPublisher";

    // CRL issuing points
    public final static String SC_CRLIPS = "crlIPs";

    // CRL extensions
    public final static String SC_CRLEXTS_RULES = "crlExtsRules";

    public final static String SC_OCSPSTORES_RULES = "ocspStoresRules";
    public final static String SC_OCSPSTORE_DEFAULT = "ocspStoreDef";

    // KRA
    public final static String SC_AUTO_RECOVERY = "autoRecovery";
    public final static String SC_RECOVERY = "recovery";
    public final static String SC_AGENT_PWD = "agentPwd";
    public final static String SC_MNSCHEME = "mnScheme";

    //stat
    public final static String SC_STAT = "stat";

    // RA
    public final static String SC_GENERAL = "general";
    public final static String SC_CLM = "clm";
    public final static String SC_PKIGW = "pkigw";
    public final static String SC_SERVLET = "servlet";
    public final static String SC_CONNECTOR = "connector";

    //tasks
    public final static String SC_TASKS = "tasks";

    //authentication
    public final static String SC_AUTH = "auths";
    public final static String SC_AUTHTYPE = "authType";
    public final static String SC_AUTH_IMPLS = "impl";
    public final static String SC_AUTH_MGR_INSTANCE = "instance";

    //jobs scheduler
    public final static String SC_JOBS = "jobScheduler";
    public final static String SC_JOBS_IMPLS = "impl";
    public final static String SC_JOBS_INSTANCE = "job";
    public final static String SC_JOBS_RULES = "rules";

    //notification
    public final static String SC_NOTIFICATION_REQ_COMP = "notificationREQC";
    public final static String SC_NOTIFICATION_REV_COMP = "notificationREVC";
    public final static String SC_NOTIFICATION_RIQ = "notificationRIQ";

    // acl
    public final static String SC_ACL_IMPLS = "impl";
    public final static String SC_ACL = "acls";
    public final static String SC_EVALUATOR_TYPES = "evaluatorTypes";

    // token
    public final static String SC_TOKEN = "token";

    // keycert
    public final static String SC_CA_SIGNINGCERT = "caSigningCert";
    public final static String SC_RA_SIGNINGCERT = "raSigningCert";
    public final static String SC_KRA_TRANSPORTCERT = "kraTransportCert";
    public final static String SC_SERVER_CERT = "serverCert";
    public final static String SC_SERVER_CERTCHAIN = "serverCertChain";
    public final static String SC_TRUSTED_CACERT = "trustedCACert";
    public final static String SC_TRUSTED_CERT = "trustedCert";
    public final static String SC_SUBJECT_NAME = "subjectName";
    public final static String SC_CERTINFO = "certInfo";
    public final static String SC_CERT_REQUEST = "certRequest";
    public final static String SC_ISSUE_IMPORT_CERT = "issueImportCert";
    public final static String SC_INSTALL_CERT = "installCert";
    public final static String SC_IMPORT_CROSS_CERT = "importXCert";
    public final static String SC_CA_CERTLIST = "caCertList";
    public final static String SC_ALL_CERTLIST = "allCertList";
    public final static String SC_DELETE_CERTS = "deleteCert";
    public final static String SC_CERT_PRETTY_PRINT = "certPrint";
    public final static String SC_TRUST = "trust";

    // Key Pair
    public final static String SC_KEY_LENGTH = "keyLength";
    public final static String SC_KEY_CURVENAME = "keyCurveName";
    public final static String SC_CERTIFICATE_EXTENSION = "certificateExt";
    public final static String SC_TOKEN_STATUS = "tokenStatus";
    public final static String SC_TOKEN_LOGON = "tokenLogon";

    public final static String SC_EXTENDED_PLUGIN_INFO = "extendedPluginInfo";

    public final static String SC_USER_TYPE = "userType";
    public final static String SC_PLATFORM = "platform";

    public final static String SC_GET_NICKNAMES = "getNicknames";

    // Profile
    public final static String SC_SUPPORTED_CONSTRAINTPOLICIES = "supportedConstraintPolicies";

    // Manage certificate admin
    public final static String SC_USERCERTSLIST = "userCertsList";
    public final static String SC_TKSKEYSLIST = "tksKeysList";
    public final static String SC_ROOTCERTSLIST = "rootCertsList";
    public final static String SC_ROOTCERT_TRUSTBIT = "rootTrustBit";
}
