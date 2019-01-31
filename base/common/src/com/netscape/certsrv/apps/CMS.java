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
package com.netscape.certsrv.apps;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Hashtable;
import java.util.Locale;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.authentication.ISharedToken;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.authorization.IAuthzSubsystem;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISecurityDomainSessionTable;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.connector.IRemoteAuthority;
import com.netscape.certsrv.connector.IResender;
import com.netscape.certsrv.dbs.IDBSubsystem;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.jobs.IJobsScheduler;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.logging.ILogSubsystem;
import com.netscape.certsrv.notification.IMailNotification;
import com.netscape.certsrv.ocsp.IOCSPAuthority;
import com.netscape.certsrv.password.IPasswordCheck;
import com.netscape.certsrv.profile.IProfileSubsystem;
import com.netscape.certsrv.ra.IRegistrationAuthority;
import com.netscape.certsrv.registry.IPluginRegistry;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.security.ICryptoSubsystem;
import com.netscape.certsrv.selftests.ISelfTestSubsystem;
import com.netscape.certsrv.tks.ITKSAuthority;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.cmsutil.password.IPasswordStore;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSSLSocketFactoryExt;

/**
 * This represents the CMS server. Plugins can access other
 * public objects such as subsystems via this inteface.
 * This object also include a set of utility functions.
 *
 * This object does not include the actual implementation.
 * It acts as a public interface for plugins, and the
 * actual implementation is in the CMS engine
 * (com.netscape.cmscore.apps.CMSEngine) that implements
 * ICMSEngine interface.
 *
 * @version $Revision$, $Date$
 */
public final class CMS {

    public static Logger logger = LoggerFactory.getLogger(CMS.class);

    public static final int DEBUG_OBNOXIOUS = 1;
    public static final int DEBUG_VERBOSE = 5;
    public static final int DEBUG_INFORM = 10;

    public static final String CONFIG_FILE = "CS.cfg";
    private static ICMSEngine _engine = null;

    public static final String SUBSYSTEM_LOG = ILogSubsystem.ID;
    public static final String SUBSYSTEM_CRYPTO = ICryptoSubsystem.ID;
    public static final String SUBSYSTEM_DBS = IDBSubsystem.SUB_ID;
    public static final String SUBSYSTEM_CA = ICertificateAuthority.ID;
    public static final String SUBSYSTEM_RA = IRegistrationAuthority.ID;
    public static final String SUBSYSTEM_KRA = IKeyRecoveryAuthority.ID;
    public static final String SUBSYSTEM_OCSP = IOCSPAuthority.ID;
    public static final String SUBSYSTEM_TKS = ITKSAuthority.ID;
    public static final String SUBSYSTEM_UG = IUGSubsystem.ID;
    public static final String SUBSYSTEM_AUTH = IAuthSubsystem.ID;
    public static final String SUBSYSTEM_AUTHZ = IAuthzSubsystem.ID;
    public static final String SUBSYSTEM_REGISTRY = IPluginRegistry.ID;
    public static final String SUBSYSTEM_PROFILE = IProfileSubsystem.ID;
    public static final String SUBSYSTEM_JOBS = IJobsScheduler.ID;
    public static final String SUBSYSTEM_SELFTESTS = ISelfTestSubsystem.ID;
    public static final int PRE_OP_MODE = 0;
    public static final int RUNNING_MODE = 1;

    /**
     * Private constructor.
     *
     * @param engine CMS engine implementation
     */
    private CMS(ICMSEngine engine) {
        _engine = engine;
    }

    public static ICMSEngine getCMSEngine() {
        return _engine;
    }

    /**
     * This method is used for unit tests. It allows the underlying _engine
     * to be stubbed out.
     *
     * @param engine The stub engine to set, for testing.
     */
    public static void setCMSEngine(ICMSEngine engine) {
        _engine = engine;
    }

    public static void checkForAndAutoShutdown() {
        _engine.checkForAndAutoShutdown();
    }

    public static boolean isPreOpMode() {
        return _engine.isPreOpMode();
    }

    public static boolean isRunningMode() {
        return _engine.isRunningMode();
    }

    /**
     * Is the server in running state. After server startup, the
     * server will be initialization state first. After the
     * initialization state, the server will be in the running
     * state.
     *
     * @return true if the server is in the running state
     */
    public static boolean isInRunningState() {
        return _engine.isInRunningState();
    }

    /**
     * Creates an issuing poing record.
     *
     * @return issuing record
     */
    public static ICRLIssuingPointRecord createCRLIssuingPointRecord(String id, BigInteger crlNumber, Long crlSize,
            Date thisUpdate, Date nextUpdate) {
        return _engine.createCRLIssuingPointRecord(id, crlNumber, crlSize, thisUpdate, nextUpdate);
    }

    /**
     * Retrieves the default CRL issuing point record name.
     *
     * @return CRL issuing point record name
     */
    public static String getCRLIssuingPointRecordName() {
        return _engine.getCRLIssuingPointRecordName();
    }

    /**
     * Retrieves the process id of this server.
     *
     * @return process id of the server
     */
    public static int getPID() {
        return _engine.getPID();
    }

    /**
     * Retrieves the instance roort path of this server.
     *
     * @return instance directory path name
     */
    public static String getInstanceDir() {
        return _engine.getInstanceDir();
    }

    /**
     * Returns a server wide system time. Plugins should call
     * this method to retrieve system time.
     *
     * @return current time
     */
    public static Date getCurrentDate() {
        if (_engine == null)
            return new Date();
        return _engine.getCurrentDate();
    }

    /**
     * Puts a message into the debug file.
     *
     * @param msg debugging message
     */
    public static void debug(String msg) {
        if (_engine != null)
            _engine.debug(msg);
    }

    /**
     * Puts an exception into the debug file.
     *
     * @param e exception
     */
    public static void debug(Throwable e) {
        if (_engine != null)
            _engine.debug(e);
    }

    /**
     * Checks if the debug mode is on or not.
     *
     * @return true if debug mode is on
     */
    public static boolean debugOn() {
        if (_engine != null)
            return _engine.debugOn();
        return false;
    }

    /**
     * Puts the current stack trace in the debug file.
     */
    public static void debugStackTrace() {
        if (_engine != null)
            _engine.debugStackTrace();
    }

    /*
     * If debugging for the particular realm is enabled, output name/value
     * pair info to the debug file. This is useful to dump out what hidden
     * config variables the server is looking at, or what HTTP variables it
     * is expecting to find, or what database attributes it is looking for.
     * @param type indicates what the source of key/val is. For example,
     *     this could be 'CS.cfg', or something else. In the debug
     *     subsystem, there is a mechanism to filter this so only the types
     *     you care about are listed
     * @param key  the 'key' of the hashtable which is being accessed.
     *     This could be the name of the config parameter, or the http param
     *     name.
     * @param val  the value of the parameter
     * @param default the default value if the param is not found
     */

    public static void traceHashKey(String type, String key) {
        if (_engine != null) {
            _engine.traceHashKey(type, key);
        }
    }

    public static void traceHashKey(String type, String key, String val) {
        if (_engine != null) {
            _engine.traceHashKey(type, key, val);
        }
    }

    public static void traceHashKey(String type, String key, String val, String def) {
        if (_engine != null) {
            _engine.traceHashKey(type, key, val, def);
        }
    }

    public static byte[] getPKCS7(Locale locale, IRequest req) {
        return _engine.getPKCS7(locale, req);
    }

    /**
     * Retrieves the registered subsytem with the given name.
     *
     * @param name subsystem name
     * @return subsystem of the given name
     */
    public static ISubsystem getSubsystem(String name) {
        return _engine.getSubsystem(name);
    }

    /**
     * Retrieves the localized user message from UserMessages.properties.
     *
     * @param msgID message id defined in UserMessages.properties
     * @return localized user message
     */
    public static String getUserMessage(String msgID) {
        if (_engine == null)
            return msgID;
        return _engine.getUserMessage(null /* from session context */, msgID);
    }

    /**
     * Retrieves the localized user message from UserMessages.properties.
     *
     * @param locale end-user locale
     * @param msgID message id defined in UserMessages.properties
     * @return localized user message
     */
    public static String getUserMessage(Locale locale, String msgID) {
        if (_engine == null)
            return msgID;
        return _engine.getUserMessage(locale, msgID);
    }

    /**
     * Retrieves the localized user message from UserMessages.properties.
     *
     * @param msgID message id defined in UserMessages.properties
     * @param p1 1st parameter
     * @return localized user message
     */
    public static String getUserMessage(String msgID, String p1) {
        if (_engine == null)
            return msgID;
        return _engine.getUserMessage(null /* from session context */, msgID, p1);
    }

    /**
     * Retrieves the localized user message from UserMessages.properties.
     *
     * @param locale end-user locale
     * @param msgID message id defined in UserMessages.properties
     * @param p1 1st parameter
     * @return localized user message
     */
    public static String getUserMessage(Locale locale, String msgID, String p1) {
        if (_engine == null)
            return msgID;
        return _engine.getUserMessage(locale, msgID, p1);
    }

    /**
     * Retrieves the localized user message from UserMessages.properties.
     *
     * @param msgID message id defined in UserMessages.properties
     * @param p1 1st parameter
     * @param p2 2nd parameter
     * @return localized user message
     */
    public static String getUserMessage(String msgID, String p1, String p2) {
        if (_engine == null)
            return msgID;
        return _engine.getUserMessage(null /* from session context */, msgID, p1, p2);
    }

    /**
     * Retrieves the localized user message from UserMessages.properties.
     *
     * @param locale end-user locale
     * @param msgID message id defined in UserMessages.properties
     * @param p1 1st parameter
     * @param p2 2nd parameter
     * @return localized user message
     */
    public static String getUserMessage(Locale locale, String msgID, String p1, String p2) {
        if (_engine == null)
            return msgID;
        return _engine.getUserMessage(locale, msgID, p1, p2);
    }

    /**
     * Retrieves the localized user message from UserMessages.properties.
     *
     * @param msgID message id defined in UserMessages.properties
     * @param p1 1st parameter
     * @param p2 2nd parameter
     * @param p3 3rd parameter
     * @return localized user message
     */
    public static String getUserMessage(String msgID, String p1, String p2, String p3) {
        if (_engine == null)
            return msgID;
        return _engine.getUserMessage(null /* from session context */, msgID, p1, p2, p3);
    }

    public static LDAPConnection getBoundConnection(String id, String host, int port,
               int version, LDAPSSLSocketFactoryExt fac, String bindDN,
               String bindPW) throws LDAPException {
        return _engine.getBoundConnection(id, host, port, version, fac,
                         bindDN, bindPW);
    }

    /**
     * Retrieves the localized user message from UserMessages.properties.
     *
     * @param locale end-user locale
     * @param msgID message id defined in UserMessages.properties
     * @param p1 1st parameter
     * @param p2 2nd parameter
     * @param p3 3rd parameter
     * @return localized user message
     */
    public static String getUserMessage(Locale locale, String msgID, String p1, String p2, String p3) {
        if (_engine == null)
            return msgID;
        return _engine.getUserMessage(locale, msgID, p1, p2, p3);
    }

    /**
     * Retrieves the localized user message from UserMessages.properties.
     *
     * @param msgID message id defined in UserMessages.properties
     * @param p an array of parameters
     * @return localized user message
     */
    public static String getUserMessage(String msgID, String p[]) {
        if (_engine == null)
            return msgID;
        return _engine.getUserMessage(null /* from session context */, msgID, p);
    }

    /**
     * Retrieves the localized user message from UserMessages.properties.
     *
     * @param locale end-user locale
     * @param msgID message id defined in UserMessages.properties
     * @param p an array of parameters
     * @return localized user message
     */
    public static String getUserMessage(Locale locale, String msgID, String p[]) {
        if (_engine == null)
            return msgID;
        return _engine.getUserMessage(locale, msgID, p);
    }

    /**
     * Retrieves log message from LogMessages.properties or audit-events.properties.
     *
     * @param msgID message ID defined in LogMessages.properties or audit-events.properties
     * @return localized log message
     */
    public static String getLogMessage(String msgID) {
        return _engine.getLogMessage(msgID, null);
    }

    /**
     * Retrieves log message from LogMessages.properties or audit-events.properties.
     *
     * @param msgID message ID defined in LogMessages.properties or audit-events.properties
     * @param params object parameters
     * @return localized log message
     */
    public static String getLogMessage(String msgID, Object params[]) {
        return _engine.getLogMessage(msgID, params);
    }

    /**
     * Retrieves log message from LogMessages.properties or audit-events.properties.
     *
     * @param msgID message ID defined in LogMessages.properties or audit-events.properties
     * @param params string parameters
     * @return localized log message
     */
    public static String getLogMessage(String msgID, String... params) {
        return _engine.getLogMessage(msgID, params);
    }

    /**
     * Returns the main config store. It is a handle to CMS.cfg.
     *
     * @return configuration store
     */
    public static IConfigStore getConfigStore() {
        return _engine.getConfigStore();
    }

    /**
     * Retrieves time server started up.
     *
     * @return last startup time
     */
    public static long getStartupTime() {
        return _engine.getStartupTime();
    }

    /**
     * Retrieves the request sender for use with connector.
     *
     * @param authority local authority
     * @param nickname nickname of the client certificate
     * @param remote remote authority
     * @param interval timeout interval
     * @return resender
     */
    public static IResender getResender(IAuthority authority, String nickname,
            String clientCiphers,
            IRemoteAuthority remote, int interval) {
        return _engine.getResender(authority, nickname, clientCiphers, remote, interval);
    }

    /**
     * Retrieves the nickname of the server's server certificate.
     *
     * @return nickname of the server certificate
     */
    public static String getServerCertNickname() {
        return _engine.getServerCertNickname();
    }

    /**
     * Sets the nickname of the server's server certificate.
     *
     * @param tokenName name of token where the certificate is located
     * @param nickName name of server certificate
     */
    public static void setServerCertNickname(String tokenName, String nickName) {
        _engine.setServerCertNickname(tokenName, nickName);
    }

    /**
     * Sets the nickname of the server's server certificate.
     *
     * @param newName new nickname of server certificate
     */
    public static void setServerCertNickname(String newName) {
        _engine.setServerCertNickname(newName);
    }

    /**
     * Retrieves the host name of the server's secure end entity service.
     *
     * @return host name of end-entity service
     */
    public static String getEEHost() {
        return _engine.getEEHost();
    }

    /**
     * Retrieves the host name of the server's non-secure end entity service.
     *
     * @return host name of end-entity non-secure service
     */
    public static String getEENonSSLHost() {
        return _engine.getEENonSSLHost();
    }

    /**
     * Retrieves the port number of the server's non-secure end entity service.
     *
     * @return port of end-entity non-secure service
     */
    public static String getEENonSSLPort() {
        return _engine.getEENonSSLPort();
    }

    /**
     * Retrieves the host name of the server's secure end entity service.
     *
     * @return port of end-entity secure service
     */
    public static String getEESSLHost() {
        return _engine.getEESSLHost();
    }

    /**
     * Retrieves the host name of the server's secure end entity service.
     *
     * @return port of end-entity secure service
     */
    public static String getEEClientAuthSSLPort() {
        return _engine.getEEClientAuthSSLPort();
    }

    /**
     * Retrieves the port number of the server's secure end entity service.
     *
     * @return port of end-entity secure service
     */
    public static String getEESSLPort() {
        return _engine.getEESSLPort();
    }

    /**
     * Retrieves the host name of the server's agent service.
     *
     * @return host name of agent service
     */
    public static String getAgentHost() {
        return _engine.getAgentHost();
    }

    /**
     * Retrieves the port number of the server's agent service.
     *
     * @return port of agent service
     */
    public static String getAgentPort() {
        return _engine.getAgentPort();
    }

    /**
     * Retrieves the port number of the server's administration service.
     *
     * @return port of administration service
     */
    public static String getAdminPort() {
        return _engine.getAdminPort();
    }

    /**
     * Retrieves the certifcate in MIME-64 encoded format
     * with header and footer.
     *
     * @param cert certificate
     * @return base-64 format certificate
     */
    public static String getEncodedCert(X509Certificate cert) {
        return _engine.getEncodedCert(cert);
    }

    /**
     * Retrieves the email notification handler.
     *
     * @return email notification
     */
    public static IMailNotification getMailNotification() {
        return _engine.getMailNotification();
    }

    public static String getConfigSDSessionId() {
        return _engine.getConfigSDSessionId();
    }

    public static void setConfigSDSessionId(String val) {
        _engine.setConfigSDSessionId(val);
    }

    /**
     * Retrieves the password check.
     *
     * @return default password checker
     */
    public static IPasswordCheck getPasswordChecker() {
        return _engine.getPasswordChecker();
    }

    /**
     * Retrieves the SharedToken class.
     *
     * @return named SharedToken class
     */
    public static ISharedToken getSharedTokenClass(String configName) {
        return _engine.getSharedTokenClass(configName);
    }

    /**
     * Puts a password entry into the single-sign on cache.
     *
     * @param tag password tag
     * @param pw password
     */
    public static void putPasswordCache(String tag, String pw) {
        _engine.putPasswordCache(tag, pw);
    }

    public static IConfigStore createFileConfigStore(String path) throws EBaseException {
        return _engine.createFileConfigStore(path);
    }

    public static IArgBlock createArgBlock() {
        return _engine.createArgBlock();
    }

    public static IArgBlock createArgBlock(String realm, Hashtable<String, String> httpReq) {
        return _engine.createArgBlock(realm, httpReq);
    }

    public static IArgBlock createArgBlock(Hashtable<String, String> httpReq) {
        return _engine.createArgBlock(httpReq);
    }

    public static boolean isRevoked(X509Certificate[] certificates) {
        return _engine.isRevoked(certificates);
    }

    public static void setListOfVerifiedCerts(int size, long interval, long unknownStateInterval) {
        _engine.setListOfVerifiedCerts(size, interval, unknownStateInterval);
    }

    public static IPasswordStore getPasswordStore() throws EBaseException {
        return _engine.getPasswordStore();
    }

    public static ISecurityDomainSessionTable getSecurityDomainSessionTable() {
        return _engine.getSecurityDomainSessionTable();
    }

    public static String getServerStatus() {
        return _engine.getServerStatus();
    }

    public static boolean isExcludedLdapAttr(String key) {
        return _engine.isExcludedLdapAttr(key);
    }

    /**
     * Check whether the string is contains password
     *
     * @param name key string
     * @return whether key is a password or not
     */
    public static boolean isSensitive(String name) {
        return (name.startsWith("__") ||
                name.endsWith("password") ||
                name.endsWith("passwd") ||
                name.endsWith("pwd") ||
                name.equalsIgnoreCase("admin_password_again") ||
                name.equalsIgnoreCase("directoryManagerPwd") ||
                name.equalsIgnoreCase("bindpassword") ||
                name.equalsIgnoreCase("bindpwd") ||
                name.equalsIgnoreCase("passwd") ||
                name.equalsIgnoreCase("password") ||
                name.equalsIgnoreCase("pin") ||
                name.equalsIgnoreCase("pwd") ||
                name.equalsIgnoreCase("pwdagain") ||
                name.equalsIgnoreCase("uPasswd") ||
                name.equalsIgnoreCase("PASSWORD_CACHE_ADD") ||
                name.startsWith("p12Password") ||
                name.equalsIgnoreCase("host_challenge") ||
                name.equalsIgnoreCase("card_challenge") ||
                name.equalsIgnoreCase("card_cryptogram") ||
                name.equalsIgnoreCase("drm_trans_desKey") ||
                name.equalsIgnoreCase("cert_request"));
    }
}
