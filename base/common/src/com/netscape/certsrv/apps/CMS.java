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

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Vector;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSSLSocketFactoryExt;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.Extension;
import netscape.security.x509.GeneralName;
import netscape.security.x509.X509CertInfo;

import org.mozilla.jss.CryptoManager.CertificateUsage;
import org.mozilla.jss.util.PasswordCallback;

import com.netscape.certsrv.acls.EACLsException;
import com.netscape.certsrv.acls.IACL;
import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.authorization.IAuthzSubsystem;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.ICRLPrettyPrint;
import com.netscape.certsrv.base.ICertPrettyPrint;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtPrettyPrint;
import com.netscape.certsrv.base.IPrettyPrintFormat;
import com.netscape.certsrv.base.ISecurityDomainSessionTable;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.ca.ICRLIssuingPoint;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.connector.IHttpConnection;
import com.netscape.certsrv.connector.IPKIMessage;
import com.netscape.certsrv.connector.IRemoteAuthority;
import com.netscape.certsrv.connector.IRequestEncoder;
import com.netscape.certsrv.connector.IResender;
import com.netscape.certsrv.dbs.IDBSubsystem;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.dbs.repository.IRepositoryRecord;
import com.netscape.certsrv.jobs.IJobsScheduler;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ILdapAuthInfo;
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.certsrv.ldap.ILdapConnInfo;
import com.netscape.certsrv.logging.IAuditor;
import com.netscape.certsrv.logging.ILogSubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.notification.IEmailFormProcessor;
import com.netscape.certsrv.notification.IEmailResolver;
import com.netscape.certsrv.notification.IEmailResolverKeys;
import com.netscape.certsrv.notification.IEmailTemplate;
import com.netscape.certsrv.notification.IMailNotification;
import com.netscape.certsrv.ocsp.IOCSPAuthority;
import com.netscape.certsrv.password.IPasswordCheck;
import com.netscape.certsrv.policy.IGeneralNameAsConstraintsConfig;
import com.netscape.certsrv.policy.IGeneralNamesAsConstraintsConfig;
import com.netscape.certsrv.policy.IGeneralNamesConfig;
import com.netscape.certsrv.policy.ISubjAltNameConfig;
import com.netscape.certsrv.profile.IProfileSubsystem;
import com.netscape.certsrv.ra.IRegistrationAuthority;
import com.netscape.certsrv.registry.IPluginRegistry;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.security.ICryptoSubsystem;
import com.netscape.certsrv.selftests.ISelfTestSubsystem;
import com.netscape.certsrv.tks.ITKSAuthority;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.cmsutil.net.ISocketFactory;
import com.netscape.cmsutil.password.IPasswordStore;

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

    public static final int DEBUG_OBNOXIOUS = 10;
    public static final int DEBUG_VERBOSE = 5;
    public static final int DEBUG_INFORM = 1;

    private static final String CONFIG_FILE = "CS.cfg";
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

    /**
     * This method is used for unit tests. It allows the underlying _engine
     * to be stubbed out.
     *
     * @param engine The stub engine to set, for testing.
     */
    public static void setCMSEngine(ICMSEngine engine) {
        _engine = engine;
    }

    /**
     * Gets this ID .
     *
     * @return CMS engine identifier
     */
    public static String getId() {
        return _engine.getId();
    }

    /**
     * Sets the identifier of this subsystem. Should never be called.
     * Returns error.
     *
     * @param id CMS engine identifier
     */
    public static void setId(String id) throws EBaseException {
        _engine.setId(id);
    }

    /**
     * Initialize all static, dynamic and final static subsystems.
     *
     * @param owner null
     * @param config main config store.
     * @exception EBaseException if any error occur in subsystems during
     *                initialization.
     */
    public static void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        _engine.init(owner, config);
    }

    public static void reinit(String id) throws EBaseException {
        _engine.reinit(id);
    }

    /**
     * Starts up all subsystems. subsystems must be initialized.
     *
     * @exception EBaseException if any subsystem fails to startup.
     */
    public static void startup() throws EBaseException {
        _engine.startup();
    }

    /**
     * Blocks all new incoming requests.
     */
    public static void disableRequests() {
        _engine.disableRequests();
    }

    /**
     * Terminates all requests that are currently in process.
     */
    public static void terminateRequests() {
        _engine.terminateRequests();
    }

    /**
     * Checks to ensure that all new incoming requests have been blocked.
     * This method is used for reentrancy protection.
     * <P>
     *
     * @return true or false
     */
    public static boolean areRequestsDisabled() {
        return _engine.areRequestsDisabled();
    }

    /**
     * Shuts down subsystems in backwards order
     * exceptions are ignored. process exists at end to force exit.
     */
    public static void shutdown() {
        _engine.shutdown();
    }

    /**
     * Shuts down subsystems in backwards order
     * exceptions are ignored. process exists at end to force exit.
     */

    public static void forceShutdown() {

        _engine.forceShutdown();
    }

    /**
     * mode = 0 (pre-operational)
     * mode = 1 (running)
     */
    public static void setCSState(int mode) {
        _engine.setCSState(mode);
    }

    public static int getCSState() {
        return _engine.getCSState();
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
     * Returns the logger of the current server. The logger can
     * be used to log critical informational or critical error
     * messages.
     *
     * @return logger
     */
    public static ILogger getLogger() {
        return _engine.getLogger();
    }

    /**
     * Returns the auditor of the current server. The auditor can
     * be used to audit critical informational or critical error
     * messages.
     *
     * @return auditor
     */
    public static IAuditor getAuditor() {
        return _engine.getAuditor();
    }

    /**
     * Returns the signed audit logger of the current server. This logger can
     * be used to log critical informational or critical error
     * messages.
     *
     * @return signed audit logger
     */
    public static ILogger getSignedAuditLogger() {
        return _engine.getSignedAuditLogger();
    }

    /**
     * Creates a repository record in the internal database.
     *
     * @return repository record
     */
    public static IRepositoryRecord createRepositoryRecord() {
        return _engine.createRepositoryRecord();
    }

    /**
     * Parse ACL resource attributes
     *
     * @param resACLs same format as the resourceACLs attribute:
     *
     *            <PRE>
     *     <resource name>:<permission1,permission2,...permissionn>:
     *     <allow|deny> (<subset of the permission set>) <evaluator expression>
     * </PRE>
     * @exception EACLsException ACL related parsing errors for resACLs
     * @return an ACL instance built from the parsed resACLs
     */
    public static IACL parseACL(String resACLs) throws EACLsException {
        return _engine.parseACL(resACLs);
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
     * Puts data of an byte array into the debug file.
     *
     * @param data byte array to be recorded in the debug file
     */
    public static void debug(byte data[]) {
        if (_engine != null)
            _engine.debug(data);
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
     * Puts a message into the debug file.
     *
     * @param level 0-10 (0 is less detail, 10 is more detail)
     * @param msg debugging message
     */
    public static void debug(int level, String msg) {
        if (_engine != null)
            _engine.debug(level, msg);
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

    /**
     * Returns the names of all the registered subsystems.
     *
     * @return a list of string-based subsystem names
     */
    public static Enumeration<String> getSubsystemNames() {
        return _engine.getSubsystemNames();
    }

    public static byte[] getPKCS7(Locale locale, IRequest req) {
        return _engine.getPKCS7(locale, req);
    }

    /**
     * Returns all the registered subsystems.
     *
     * @return a list of ISubsystem-based subsystems
     */
    public static Enumeration<ISubsystem> getSubsystems() {
        return _engine.getSubsystems();
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

    public static LDAPConnection getBoundConnection(String host, int port,
               int version, LDAPSSLSocketFactoryExt fac, String bindDN,
               String bindPW) throws LDAPException {
        return _engine.getBoundConnection(host, port, version, fac,
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
     * Retrieves the centralized log message from LogMessages.properties.
     *
     * @param msgID message id defined in LogMessages.properties
     * @return localized log message
     */
    public static String getLogMessage(String msgID) {
        return _engine.getLogMessage(msgID);
    }

    /**
     * Retrieves the centralized log message from LogMessages.properties.
     *
     * @param msgID message id defined in LogMessages.properties
     * @param p an array of parameters
     * @return localized log message
     */
    public static String getLogMessage(String msgID, String p[]) {
        return _engine.getLogMessage(msgID, p);
    }

    /**
     * Retrieves the centralized log message from LogMessages.properties.
     *
     * @param msgID message id defined in LogMessages.properties
     * @param p1 1st parameter
     * @return localized log message
     */
    public static String getLogMessage(String msgID, String p1) {
        return _engine.getLogMessage(msgID, p1);
    }

    /**
     * Retrieves the centralized log message from LogMessages.properties.
     *
     * @param msgID message id defined in LogMessages.properties
     * @param p1 1st parameter
     * @param p2 2nd parameter
     * @return localized log message
     */
    public static String getLogMessage(String msgID, String p1, String p2) {
        return _engine.getLogMessage(msgID, p1, p2);
    }

    /**
     * Retrieves the centralized log message from LogMessages.properties.
     *
     * @param msgID message id defined in LogMessages.properties
     * @param p1 1st parameter
     * @param p2 2nd parameter
     * @param p3 3rd parameter
     * @return localized log message
     */
    public static String getLogMessage(String msgID, String p1, String p2, String p3) {
        return _engine.getLogMessage(msgID, p1, p2, p3);
    }

    /**
     * Retrieves the centralized log message from LogMessages.properties.
     *
     * @param msgID message id defined in LogMessages.properties
     * @param p1 1st parameter
     * @param p2 2nd parameter
     * @param p3 3rd parameter
     * @param p4 4th parameter
     * @return localized log message
     */
    public static String getLogMessage(String msgID, String p1, String p2, String p3, String p4) {
        return _engine.getLogMessage(msgID, p1, p2, p3, p4);
    }

    /**
     * Retrieves the centralized log message from LogMessages.properties.
     *
     * @param msgID message id defined in LogMessages.properties
     * @param p1 1st parameter
     * @param p2 2nd parameter
     * @param p3 3rd parameter
     * @param p4 4th parameter
     * @param p5 5th parameter
     * @return localized log message
     */
    public static String getLogMessage(String msgID, String p1, String p2, String p3, String p4, String p5) {
        return _engine.getLogMessage(msgID, p1, p2, p3, p4, p5);
    }

    /**
     * Retrieves the centralized log message from LogMessages.properties.
     *
     * @param msgID message id defined in LogMessages.properties
     * @param p1 1st parameter
     * @param p2 2nd parameter
     * @param p3 3rd parameter
     * @param p4 4th parameter
     * @param p5 5th parameter
     * @param p6 6th parameter
     * @return localized log message
     */
    public static String getLogMessage(String msgID, String p1, String p2, String p3, String p4, String p5, String p6) {
        return _engine.getLogMessage(msgID, p1, p2, p3, p4, p5, p6);
    }

    /**
     * Retrieves the centralized log message from LogMessages.properties.
     *
     * @param msgID message id defined in LogMessages.properties
     * @param p1 1st parameter
     * @param p2 2nd parameter
     * @param p3 3rd parameter
     * @param p4 4th parameter
     * @param p5 5th parameter
     * @param p6 6th parameter
     * @param p7 7th parameter
     * @return localized log message
     */
    public static String getLogMessage(String msgID, String p1, String p2, String p3, String p4, String p5, String p6,
            String p7) {
        return _engine.getLogMessage(msgID, p1, p2, p3, p4, p5, p6, p7);
    }

    /**
     * Retrieves the centralized log message from LogMessages.properties.
     *
     * @param msgID message id defined in LogMessages.properties
     * @param p1 1st parameter
     * @param p2 2nd parameter
     * @param p3 3rd parameter
     * @param p4 4th parameter
     * @param p5 5th parameter
     * @param p6 6th parameter
     * @param p7 7th parameter
     * @param p8 8th parameter
     * @return localized log message
     */
    public static String getLogMessage(String msgID, String p1, String p2, String p3, String p4, String p5, String p6,
            String p7, String p8) {
        return _engine.getLogMessage(msgID, p1, p2, p3, p4, p5, p6, p7, p8);
    }

    /**
     * Retrieves the centralized log message from LogMessages.properties.
     *
     * @param msgID message id defined in LogMessages.properties
     * @param p1 1st parameter
     * @param p2 2nd parameter
     * @param p3 3rd parameter
     * @param p4 4th parameter
     * @param p5 5th parameter
     * @param p6 6th parameter
     * @param p7 7th parameter
     * @param p8 8th parameter
     * @param p9 9th parameter
     * @return localized log message
     */
    public static String getLogMessage(String msgID, String p1, String p2, String p3, String p4, String p5, String p6,
            String p7, String p8, String p9) {
        return _engine.getLogMessage(msgID, p1, p2, p3, p4, p5, p6, p7, p8, p9);
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
     * Retrieves the HTTP Connection for use with connector.
     *
     * @param authority remote authority
     * @param factory socket factory
     * @return http connection to the remote authority
     */
    public static IHttpConnection getHttpConnection(IRemoteAuthority authority,
            ISocketFactory factory) {
        return _engine.getHttpConnection(authority, factory);
    }

    /**
     * Retrieves the HTTP Connection for use with connector.
     *
     * @param authority remote authority
     * @param factory socket factory
     * @param timeout return error if connection cannot be established within
     *            the timeout period
     * @return http connection to the remote authority
     */
    public static IHttpConnection getHttpConnection(IRemoteAuthority authority,
            ISocketFactory factory, int timeout) {
        return _engine.getHttpConnection(authority, factory, timeout);
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
            IRemoteAuthority remote, int interval) {
        return _engine.getResender(authority, nickname, remote, interval);
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
     * Retrieves the IP address of the server's non-secure end entity service.
     *
     * @return ip address of end-entity non-secure service
     */
    public static String getEENonSSLIP() {
        return _engine.getEENonSSLIP();
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
     * Retrieves the IP address of the server's secure end entity service.
     *
     * @return ip address of end-entity secure service
     */
    public static String getEESSLIP() {
        return _engine.getEESSLIP();
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
     * Retrieves the IP address of the server's agent service.
     *
     * @return ip address of agent service
     */
    public static String getAgentIP() {
        return _engine.getAgentIP();
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
     * Retrieves the host name of the server's administration service.
     *
     * @return host name of administration service
     */
    public static String getAdminHost() {
        return _engine.getAdminHost();
    }

    /**
     * Retrieves the IP address of the server's administration service.
     *
     * @return ip address of administration service
     */
    public static String getAdminIP() {
        return _engine.getAdminIP();
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
     * Creates a general name constraints.
     *
     * @param generalNameChoice type of general name
     * @param value general name string
     * @return general name object
     * @exception EBaseException failed to create general name constraint
     */
    public static GeneralName form_GeneralNameAsConstraints(String generalNameChoice, String value)
            throws EBaseException {
        return _engine.form_GeneralName(generalNameChoice, value);
    }

    /**
     * Creates a general name.
     *
     * @param generalNameChoice type of general name
     * @param value general name string
     * @return general name object
     * @exception EBaseException failed to create general name
     */
    public static GeneralName form_GeneralName(String generalNameChoice,
            String value) throws EBaseException {
        return _engine.form_GeneralName(generalNameChoice, value);
    }

    /**
     * Get default parameters for subject alt name configuration.
     *
     * @param name configuration name
     * @param params configuration parameters
     */
    public static void getSubjAltNameConfigDefaultParams(String name,
            Vector<String> params) {
        _engine.getSubjAltNameConfigDefaultParams(name, params);
    }

    /**
     * Get extended plugin info for subject alt name configuration.
     *
     * @param name configuration name
     * @param params configuration parameters
     */
    public static void getSubjAltNameConfigExtendedPluginInfo(String name,
            Vector<String> params) {
        _engine.getSubjAltNameConfigExtendedPluginInfo(name, params);
    }

    /**
     * Creates subject alt name configuration.
     *
     * @param name configuration name
     * @param config configuration store
     * @param isValueConfigured true if value is configured
     * @exception EBaseException failed to create subject alt name configuration
     */
    public static ISubjAltNameConfig createSubjAltNameConfig(String name, IConfigStore config, boolean isValueConfigured)
            throws EBaseException {
        return _engine.createSubjAltNameConfig(
                name, config, isValueConfigured);
    }

    /**
     * Retrieves default general name configuration.
     *
     * @param name configuration name
     * @param isValueConfigured true if value is configured
     * @param params configuration parameters
     * @exception EBaseException failed to create subject alt name configuration
     */
    public static void getGeneralNameConfigDefaultParams(String name,
            boolean isValueConfigured, Vector<String> params) {
        _engine.getGeneralNameConfigDefaultParams(name,
                isValueConfigured, params);
    }

    /**
     * Retrieves default general names configuration.
     *
     * @param name configuration name
     * @param isValueConfigured true if value is configured
     * @param params configuration parameters
     * @exception EBaseException failed to create subject alt name configuration
     */
    public static void getGeneralNamesConfigDefaultParams(String name,
            boolean isValueConfigured, Vector<String> params) {
        _engine.getGeneralNamesConfigDefaultParams(name,
                isValueConfigured, params);
    }

    /**
     * Retrieves extended plugin info for general name configuration.
     *
     * @param name configuration name
     * @param isValueConfigured true if value is configured
     * @param info configuration parameters
     * @exception EBaseException failed to create subject alt name configuration
     */
    public static void getGeneralNameConfigExtendedPluginInfo(String name,
            boolean isValueConfigured, Vector<String> info) {
        _engine.getGeneralNameConfigExtendedPluginInfo(name,
                isValueConfigured, info);
    }

    /**
     * Retrieves extended plugin info for general name configuration.
     *
     * @param name configuration name
     * @param isValueConfigured true if value is configured
     * @param info configuration parameters
     * @exception EBaseException failed to create subject alt name configuration
     */
    public static void getGeneralNamesConfigExtendedPluginInfo(String name,
            boolean isValueConfigured, Vector<String> info) {
        _engine.getGeneralNamesConfigExtendedPluginInfo(name,
                isValueConfigured, info);
    }

    /**
     * Created general names configuration.
     *
     * @param name configuration name
     * @param config configuration store
     * @param isValueConfigured true if value is configured
     * @param isPolicyEnabled true if policy is enabled
     * @exception EBaseException failed to create subject alt name configuration
     */
    public static IGeneralNamesConfig createGeneralNamesConfig(String name,
            IConfigStore config, boolean isValueConfigured,
            boolean isPolicyEnabled) throws EBaseException {
        return _engine.createGeneralNamesConfig(name, config, isValueConfigured,
                isPolicyEnabled);
    }

    /**
     * Created general name constraints configuration.
     *
     * @param name configuration name
     * @param config configuration store
     * @param isValueConfigured true if value is configured
     * @param isPolicyEnabled true if policy is enabled
     * @exception EBaseException failed to create subject alt name configuration
     */
    public static IGeneralNameAsConstraintsConfig createGeneralNameAsConstraintsConfig(String name,
            IConfigStore config, boolean isValueConfigured,
            boolean isPolicyEnabled) throws EBaseException {
        return _engine.createGeneralNameAsConstraintsConfig(
                name, config, isValueConfigured, isPolicyEnabled);
    }

    /**
     * Created general name constraints configuration.
     *
     * @param name configuration name
     * @param config configuration store
     * @param isValueConfigured true if value is configured
     * @param isPolicyEnabled true if policy is enabled
     * @exception EBaseException failed to create subject alt name configuration
     */
    public static IGeneralNamesAsConstraintsConfig createGeneralNamesAsConstraintsConfig(String name,
            IConfigStore config, boolean isValueConfigured,
            boolean isPolicyEnabled) throws EBaseException {
        return _engine.createGeneralNamesAsConstraintsConfig(
                name, config, isValueConfigured, isPolicyEnabled);
    }

    /**
     * Returns the finger print of the given certificate.
     *
     * @param cert certificate
     * @return finger print of certificate
     */
    public static String getFingerPrint(Certificate cert)
            throws CertificateEncodingException, NoSuchAlgorithmException {
        return _engine.getFingerPrint(cert);
    }

    /**
     * Returns the finger print of the given certificate.
     *
     * @param certDer DER byte array of the certificate
     * @return finger print of certificate
     */
    public static String getFingerPrints(byte[] certDer)
            throws NoSuchAlgorithmException {
        return _engine.getFingerPrints(certDer);
    }

    /**
     * Returns the finger print of the given certificate.
     *
     * @param cert certificate
     * @return finger print of certificate
     */
    public static String getFingerPrints(Certificate cert)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        return _engine.getFingerPrints(cert);
    }

    /**
     * Creates a HTTP PKI Message that can be sent to a remote
     * authority.
     *
     * @return a new PKI Message for remote authority
     */
    public static IPKIMessage getHttpPKIMessage() {
        return _engine.getHttpPKIMessage();
    }

    /**
     * Creates a request encoder. A request cannot be sent to
     * the remote authority in its regular format.
     *
     * @return a request encoder
     */
    public static IRequestEncoder getHttpRequestEncoder() {
        return _engine.getHttpRequestEncoder();
    }

    /**
     * Converts a BER-encoded byte array into a MIME-64 encoded string.
     *
     * @param data data in byte array format
     * @return base-64 encoding for the data
     */
    public static String BtoA(byte data[]) {
        return _engine.BtoA(data);
    }

    /**
     * Converts a MIME-64 encoded string into a BER-encoded byte array.
     *
     * @param data base-64 encoding for the data
     * @return data data in byte array format
     */
    public static byte[] AtoB(String data) {
        return _engine.AtoB(data);
    }

    /**
     * Retrieves the ldap connection information from the configuration
     * store.
     *
     * @param config configuration parameters of ldap connection
     * @return a LDAP connection info
     */
    public static ILdapConnInfo getLdapConnInfo(IConfigStore config)
            throws EBaseException, ELdapException {
        return _engine.getLdapConnInfo(config);
    }

    /**
     * Creates a LDAP SSL socket with the given nickname. The
     * certificate associated with the nickname will be used
     * for client authentication.
     *
     * @param certNickname nickname of client certificate
     * @return LDAP SSL socket factory
     */
    public static LDAPSSLSocketFactoryExt getLdapJssSSLSocketFactory(
            String certNickname) {
        return _engine.getLdapJssSSLSocketFactory(certNickname);
    }

    /**
     * Creates a LDAP SSL socket.
     *
     * @return LDAP SSL socket factory
     */
    public static LDAPSSLSocketFactoryExt getLdapJssSSLSocketFactory() {
        return _engine.getLdapJssSSLSocketFactory();
    }

    /**
     * Creates a LDAP Auth Info object.
     *
     * @return LDAP authentication info
     */
    public static ILdapAuthInfo getLdapAuthInfo() {
        return _engine.getLdapAuthInfo();
    }

    /**
     * Retrieves the LDAP connection factory.
     *
     * @return bound LDAP connection pool
     */
    public static ILdapConnFactory getLdapBoundConnFactory()
            throws ELdapException {
        return _engine.getLdapBoundConnFactory();
    }

    /**
     * Retrieves the LDAP connection factory.
     *
     * @return anonymous LDAP connection pool
     */
    public static ILdapConnFactory getLdapAnonConnFactory()
            throws ELdapException {
        return _engine.getLdapAnonConnFactory();
    }

    /**
     * Retrieves the default X.509 certificate template.
     *
     * @return default certificate template
     */
    public static X509CertInfo getDefaultX509CertInfo() {
        return _engine.getDefaultX509CertInfo();
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
     * Verifies all system certs
     * with tags defined in <subsystemtype>.cert.list
     */
    public static boolean verifySystemCerts() {
        return _engine.verifySystemCerts();
    }

    /**
     * Verify a system cert by tag name
     * with tags defined in <subsystemtype>.cert.list
     */
    public static boolean verifySystemCertByTag(String tag) {
        return _engine.verifySystemCertByTag(tag);
    }

    /**
     * Verify a system cert by certificate nickname
     */
    public static boolean verifySystemCertByNickname(String nickname, String certificateUsage) {
        return _engine.verifySystemCertByNickname(nickname, certificateUsage);
    }

    /**
     * get the CertificateUsage as defined in JSS CryptoManager
     */
    public static CertificateUsage getCertificateUsage(String certusage) {
        return _engine.getCertificateUsage(certusage);
    }

    /**
     * Checks if the given certificate is a signing certificate.
     *
     * @param cert certificate
     * @return true if the given certificate is a signing certificate
     */
    public static boolean isSigningCert(X509Certificate cert) {
        return _engine.isSigningCert(cert);
    }

    /**
     * Checks if the given certificate is an encryption certificate.
     *
     * @param cert certificate
     * @return true if the given certificate is an encryption certificate
     */
    public static boolean isEncryptionCert(X509Certificate cert) {
        return _engine.isEncryptionCert(cert);
    }

    /**
     * Retrieves the email form processor.
     *
     * @return email form processor
     */
    public static IEmailFormProcessor getEmailFormProcessor() {
        return _engine.getEmailFormProcessor();
    }

    /**
     * Retrieves the email form template.
     *
     * @return email template
     */
    public static IEmailTemplate getEmailTemplate(String path) {
        return _engine.getEmailTemplate(path);
    }

    /**
     * Retrieves the email notification handler.
     *
     * @return email notification
     */
    public static IMailNotification getMailNotification() {
        return _engine.getMailNotification();
    }

    /**
     * Retrieves the email key resolver.
     *
     * @return email key resolver
     */
    public static IEmailResolverKeys getEmailResolverKeys() {
        return _engine.getEmailResolverKeys();
    }

    /**
     * Checks if the given OID is valid.
     *
     * @param attrName attribute name
     * @param value attribute value
     * @return object identifier of the given attrName
     */
    public static ObjectIdentifier checkOID(String attrName, String value)
            throws EBaseException {
        return _engine.checkOID(attrName, value);
    }

    /**
     * Retrieves the email resolver that checks for subjectAlternateName.
     *
     * @return email key resolver
     */
    public static IEmailResolver getReqCertSANameEmailResolver() {
        return _engine.getReqCertSANameEmailResolver();
    }

    /**
     * Retrieves the extension pretty print handler.
     *
     * @param e extension
     * @param indent indentation
     * @return extension pretty print handler
     */
    public static IExtPrettyPrint getExtPrettyPrint(Extension e, int indent) {
        return _engine.getExtPrettyPrint(e, indent);
    }

    /**
     * Retrieves the certificate pretty print handler.
     *
     * @param delimiter delimiter
     * @return certificate pretty print handler
     */
    public static IPrettyPrintFormat getPrettyPrintFormat(String delimiter) {
        return _engine.getPrettyPrintFormat(delimiter);
    }

    /**
     * Retrieves the CRL pretty print handler.
     *
     * @param crl CRL
     * @return CRL pretty print handler
     */
    public static ICRLPrettyPrint getCRLPrettyPrint(X509CRL crl) {
        return _engine.getCRLPrettyPrint(crl);
    }

    /**
     * Retrieves the CRL cache pretty print handler.
     *
     * @param ip CRL issuing point
     * @return CRL pretty print handler
     */
    public static ICRLPrettyPrint getCRLCachePrettyPrint(ICRLIssuingPoint ip) {
        return _engine.getCRLCachePrettyPrint(ip);
    }

    /**
     * Retrieves the certificate pretty print handler.
     *
     * @param cert certificate
     * @return certificate pretty print handler
     */
    public static ICertPrettyPrint getCertPrettyPrint(X509Certificate cert) {
        return _engine.getCertPrettyPrint(cert);
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
     * Puts a password entry into the single-sign on cache.
     *
     * @param tag password tag
     * @param pw password
     */
    public static void putPasswordCache(String tag, String pw) {
        _engine.putPasswordCache(tag, pw);
    }

    /**
     * Retrieves the password callback.
     *
     * @return default password callback
     */
    public static PasswordCallback getPasswordCallback() {
        return _engine.getPasswordCallback();
    }

    /**
     * Retrieves command queue
     *
     * @return command queue
     */
    public static ICommandQueue getCommandQueue() {
        return _engine.getCommandQueue();
    }

    /**
     * Loads the configuration file and starts CMS's core implementation.
     *
     * @param path path to configuration file (CMS.cfg)
     * @exception EBaseException failed to start CMS
     */
    public static void start(String path) throws EBaseException {
        //FileConfigStore mainConfig = null;
        /*
                try {
                    mainConfig = new FileConfigStore(path);
                } catch (EBaseException e) {
                    e.printStackTrace();
                    System.out.println(
                        "Error: The Server is not fully configured.\n" +
                        "Finish configuring server using Configure Setup Wizard in " +
                        "the Certificate Server Console.");
                    System.out.println(e.toString());
                    System.exit(0);
                }
        */

        String classname = "com.netscape.cmscore.apps.CMSEngine";

        try {
            ICMSEngine engine = (ICMSEngine)
                    Class.forName(classname).newInstance();

            CMS.setCMSEngine(engine);
            IConfigStore mainConfig = createFileConfigStore(path);
            CMS.init(null, mainConfig);
            CMS.startup();

        } catch (EBaseException e) { // catch everything here purposely
            CMS.debug("CMS:Caught EBaseException");
            CMS.debug(e);

            // Raidzilla Bug #57592:  Always print error message to stdout.
            System.out.println(e.toString());

            shutdown();
            throw e;
        } catch (Exception e) { // catch everything here purposely
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            PrintStream ps = new PrintStream(bos);

            e.printStackTrace(ps);
            System.out.println(Constants.SERVER_SHUTDOWN_MESSAGE);
            throw new EBaseException(bos.toString());
            // cms.shutdown();
        }
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

    public static IPasswordStore getPasswordStore() {
        return _engine.getPasswordStore();
    }

    public static ISecurityDomainSessionTable getSecurityDomainSessionTable() {
        return _engine.getSecurityDomainSessionTable();
    }

    public static String getServerStatus() {
        return _engine.getServerStatus();
    }

    /**
     * Main driver to start CMS.
     */
    public static void main(String[] args) {
        String path = CONFIG_FILE;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];

            if (arg.equals("-f")) {
                path = args[++i];
            } else {
                // ignore unknown arguments since we
                // have no real way to report them
            }
        }
        try {
            start(path);
        } catch (EBaseException e) {
        }

        // Use shutdown hook in stand-alone application
        // to catch SIGINT, SIGTERM, or SIGHUP.
        Runtime.getRuntime().addShutdownHook(new Thread() {
            public void run() {
                /*LogDoc
                *
                * @phase watchdog check
                */
                CMS.getLogger().log(ILogger.EV_SYSTEM,
                        ILogger.S_OTHER,
                        ILogger.LL_INFO,
                        "CMSEngine: Received shutdown signal");

                CMS.shutdown();
            };
        });
    }
}
