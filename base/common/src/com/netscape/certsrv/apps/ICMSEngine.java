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
import com.netscape.certsrv.authority.IAuthority;
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
import com.netscape.certsrv.connector.IHttpConnection;
import com.netscape.certsrv.connector.IPKIMessage;
import com.netscape.certsrv.connector.IRemoteAuthority;
import com.netscape.certsrv.connector.IRequestEncoder;
import com.netscape.certsrv.connector.IResender;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.dbs.repository.IRepositoryRecord;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ILdapAuthInfo;
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.certsrv.ldap.ILdapConnInfo;
import com.netscape.certsrv.logging.IAuditor;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.notification.IEmailFormProcessor;
import com.netscape.certsrv.notification.IEmailResolver;
import com.netscape.certsrv.notification.IEmailResolverKeys;
import com.netscape.certsrv.notification.IEmailTemplate;
import com.netscape.certsrv.notification.IMailNotification;
import com.netscape.certsrv.password.IPasswordCheck;
import com.netscape.certsrv.policy.IGeneralNameAsConstraintsConfig;
import com.netscape.certsrv.policy.IGeneralNamesAsConstraintsConfig;
import com.netscape.certsrv.policy.IGeneralNamesConfig;
import com.netscape.certsrv.policy.ISubjAltNameConfig;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmsutil.net.ISocketFactory;
import com.netscape.cmsutil.password.IPasswordStore;

/**
 * This interface represents the CMS core framework. The
 * framework contains a set of services that provide
 * the foundation of a security application.
 * <p>
 * The engine implementation is loaded by CMS at startup. It is responsible for starting up all the related subsystems.
 * <p>
 *
 * @version $Revision$, $Date$
 */
public interface ICMSEngine extends ISubsystem {

    /**
     * Gets this ID .
     *
     * @return CMS engine identifier
     */
    public String getId();

    /**
     * Sets the identifier of this subsystem. Should never be called.
     * Returns error.
     *
     * @param id CMS engine identifier
     */
    public void setId(String id) throws EBaseException;

    /**
     * Retrieves the process id of this server.
     *
     * @return process id of the server
     */
    public int getPID();

    public void reinit(String id) throws EBaseException;

    public int getCSState();

    public void setCSState(int mode);

    public boolean isPreOpMode();

    public boolean isRunningMode();

    /**
     * Retrieves the instance roort path of this server.
     *
     * @return instance directory path name
     */
    public String getInstanceDir();

    /**
     * Returns a server wide system time. Plugins should call
     * this method to retrieve system time.
     *
     * @return current time
     */
    public Date getCurrentDate();

    /**
     * Retrieves time server started up.
     *
     * @return last startup time
     */
    public long getStartupTime();

    /**
     * Is the server in running state. After server startup, the
     * server will be initialization state first. After the
     * initialization state, the server will be in the running
     * state.
     *
     * @return true if the server is in the running state
     */
    public boolean isInRunningState();

    /**
     * Returns the names of all the registered subsystems.
     *
     * @return a list of string-based subsystem names
     */
    public Enumeration<String> getSubsystemNames();

    /**
     * Returns all the registered subsystems.
     *
     * @return a list of ISubsystem-based subsystems
     */
    public Enumeration<ISubsystem> getSubsystems();

    /**
     * Retrieves the registered subsytem with the given name.
     *
     * @param name subsystem name
     * @return subsystem of the given name
     */
    public ISubsystem getSubsystem(String name);

    /**
     * Returns the logger of the current server. The logger can
     * be used to log critical informational or critical error
     * messages.
     *
     * @return logger
     */
    public ILogger getLogger();

    /**
     * Returns the auditor of the current server. The auditor can
     * be used to audit critical informational or critical error
     * messages.
     *
     * @return auditor
     */
    public IAuditor getAuditor();

    /**
     * Returns the signed audit logger of the current server. This logger can
     * be used to log critical informational or critical error
     * messages.
     *
     * @return signed audit logger
     */
    public ILogger getSignedAuditLogger();

    /**
     * Puts data of an byte array into the debug file.
     *
     * @param data byte array to be recorded in the debug file
     */
    public void debug(byte data[]);

    /**
     * Puts a message into the debug file.
     *
     * @param msg debugging message
     */
    public void debug(String msg);

    /**
     * Puts a message into the debug file.
     *
     * @param level 0-10
     * @param msg debugging message
     */
    public void debug(int level, String msg);

    /**
     * Puts an exception into the debug file.
     *
     * @param e exception
     */
    public void debug(Throwable e);

    /**
     * Checks if the debug mode is on or not.
     *
     * @return true if debug mode is on
     */
    public boolean debugOn();

    /**
     * Puts the current stack trace in the debug file.
     */
    public void debugStackTrace();

    /**
     * Dump name/value pair debug information to debug file
     */
    public void traceHashKey(String type, String key);

    public void traceHashKey(String type, String key, String val);

    public void traceHashKey(String type, String key, String val, String def);

    public byte[] getPKCS7(Locale locale, IRequest req);

    /**
     * Retrieves the localized user message from UserMessages.properties.
     *
     * @param locale end-user locale
     * @param msgID message id defined in UserMessages.properties
     * @return localized user message
     */
    public String getUserMessage(Locale locale, String msgID);

    /**
     * Retrieves the localized user message from UserMessages.properties.
     *
     * @param locale end-user locale
     * @param msgID message id defined in UserMessages.properties
     * @param p an array of parameters
     * @return localized user message
     */
    public String getUserMessage(Locale locale, String msgID, String p[]);

    /**
     * Retrieves the localized user message from UserMessages.properties.
     *
     * @param locale end-user locale
     * @param msgID message id defined in UserMessages.properties
     * @param p1 1st parameter
     * @return localized user message
     */
    public String getUserMessage(Locale locale, String msgID, String p1);

    /**
     * Retrieves the localized user message from UserMessages.properties.
     *
     * @param locale end-user locale
     * @param msgID message id defined in UserMessages.properties
     * @param p1 1st parameter
     * @param p2 2nd parameter
     * @return localized user message
     */
    public String getUserMessage(Locale locale, String msgID, String p1, String p2);

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
    public String getUserMessage(Locale locale, String msgID, String p1, String p2, String p3);

    /**
     * Retrieves the centralized log message from LogMessages.properties.
     *
     * @param msgID message id defined in LogMessages.properties
     * @return localized log message
     */
    public String getLogMessage(String msgID);

    /**
     * Retrieves the centralized log message from LogMessages.properties.
     *
     * @param msgID message id defined in LogMessages.properties
     * @param p an array of parameters
     * @return localized log message
     */
    public String getLogMessage(String msgID, String p[]);

    /**
     * Retrieves the centralized log message from LogMessages.properties.
     *
     * @param msgID message id defined in LogMessages.properties
     * @param p1 1st parameter
     * @return localized log message
     */
    public String getLogMessage(String msgID, String p1);

    /**
     * Retrieves the centralized log message from LogMessages.properties.
     *
     * @param msgID message id defined in LogMessages.properties
     * @param p1 1st parameter
     * @param p2 2nd parameter
     * @return localized log message
     */
    public String getLogMessage(String msgID, String p1, String p2);

    /**
     * Retrieves the centralized log message from LogMessages.properties.
     *
     * @param msgID message id defined in LogMessages.properties
     * @param p1 1st parameter
     * @param p2 2nd parameter
     * @param p3 3rd parameter
     * @return localized log message
     */
    public String getLogMessage(String msgID, String p1, String p2, String p3);

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
    public String getLogMessage(String msgID, String p1, String p2, String p3, String p4);

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
    public String getLogMessage(String msgID, String p1, String p2, String p3, String p4, String p5);

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
    public String getLogMessage(String msgID, String p1, String p2, String p3, String p4, String p5, String p6);

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
    public String getLogMessage(String msgID, String p1, String p2, String p3, String p4, String p5, String p6,
            String p7);

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
    public String getLogMessage(String msgID, String p1, String p2, String p3, String p4, String p5, String p6,
            String p7, String p8);

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
    public String getLogMessage(String msgID, String p1, String p2, String p3, String p4, String p5, String p6,
            String p7, String p8, String p9);

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
    public IACL parseACL(String resACLs) throws EACLsException;

    /**
     * Creates an issuing poing record.
     *
     * @return issuing record
     */
    public ICRLIssuingPointRecord createCRLIssuingPointRecord(String id, BigInteger crlNumber, Long crlSize,
            Date thisUpdate, Date nextUpdate);

    /**
     * Retrieves the default CRL issuing point record name.
     *
     * @return CRL issuing point record name
     */
    public String getCRLIssuingPointRecordName();

    /**
     * Returns the finger print of the given certificate.
     *
     * @param cert certificate
     * @return finger print of certificate
     */
    public String getFingerPrint(Certificate cert)
            throws CertificateEncodingException, NoSuchAlgorithmException;

    /**
     * Returns the finger print of the given certificate.
     *
     * @param cert certificate
     * @return finger print of certificate
     */
    public String getFingerPrints(Certificate cert)
            throws NoSuchAlgorithmException, CertificateEncodingException;

    /*
     * Returns the finger print of the given certificate.
     *
     * @param certDer DER byte array of certificate
     * @return finger print of certificate
     */
    public String getFingerPrints(byte[] certDer)
            throws NoSuchAlgorithmException;

    /**
     * Creates a repository record in the internal database.
     *
     * @return repository record
     */
    public IRepositoryRecord createRepositoryRecord();

    /**
     * Creates a HTTP PKI Message that can be sent to a remote
     * authority.
     *
     * @return a new PKI Message for remote authority
     */
    public IPKIMessage getHttpPKIMessage();

    /**
     * Creates a request encoder. A request cannot be sent to
     * the remote authority in its regular format.
     *
     * @return a request encoder
     */
    public IRequestEncoder getHttpRequestEncoder();

    /**
     * Converts a BER-encoded byte array into a MIME-64 encoded string.
     *
     * @param data data in byte array format
     * @return base-64 encoding for the data
     */
    public String BtoA(byte data[]);

    /**
     * Converts a MIME-64 encoded string into a BER-encoded byte array.
     *
     * @param data base-64 encoding for the data
     * @return data data in byte array format
     */
    public byte[] AtoB(String data);

    /**
     * Retrieves the certifcate in MIME-64 encoded format
     * with header and footer.
     *
     * @param cert certificate
     * @return base-64 format certificate
     */
    public String getEncodedCert(X509Certificate cert);

    /**
     * Retrieves the certificate pretty print handler.
     *
     * @param delimiter delimiter
     * @return certificate pretty print handler
     */
    public IPrettyPrintFormat getPrettyPrintFormat(String delimiter);

    /**
     * Retrieves the extension pretty print handler.
     *
     * @param e extension
     * @param indent indentation
     * @return extension pretty print handler
     */
    public IExtPrettyPrint getExtPrettyPrint(Extension e, int indent);

    /**
     * Retrieves the certificate pretty print handler.
     *
     * @param cert certificate
     * @return certificate pretty print handler
     */
    public ICertPrettyPrint getCertPrettyPrint(X509Certificate cert);

    /**
     * Retrieves the CRL pretty print handler.
     *
     * @param crl CRL
     * @return CRL pretty print handler
     */
    public ICRLPrettyPrint getCRLPrettyPrint(X509CRL crl);

    /**
     * Retrieves the CRL cache pretty print handler.
     *
     * @param ip CRL issuing point
     * @return CRL pretty print handler
     */
    public ICRLPrettyPrint getCRLCachePrettyPrint(ICRLIssuingPoint ip);

    /**
     * Retrieves the ldap connection information from the configuration
     * store.
     *
     * @param config configuration parameters of ldap connection
     * @return a LDAP connection info
     */
    public ILdapConnInfo getLdapConnInfo(IConfigStore config)
            throws EBaseException, ELdapException;

    /**
     * Creates a LDAP SSL socket with the given nickname. The
     * certificate associated with the nickname will be used
     * for client authentication.
     *
     * @param certNickname nickname of client certificate
     * @return LDAP SSL socket factory
     */
    public LDAPSSLSocketFactoryExt getLdapJssSSLSocketFactory(
            String certNickname);

    /**
     * Creates a LDAP SSL socket.
     *
     * @return LDAP SSL socket factory
     */
    public LDAPSSLSocketFactoryExt getLdapJssSSLSocketFactory();

    /**
     * Creates a LDAP Auth Info object.
     *
     * @return LDAP authentication info
     */
    public ILdapAuthInfo getLdapAuthInfo();

    /**
     * Retrieves the LDAP connection factory.
     *
     * @return bound LDAP connection pool
     */
    public ILdapConnFactory getLdapBoundConnFactory() throws ELdapException;

    public LDAPConnection getBoundConnection(String host, int port,
               int version, LDAPSSLSocketFactoryExt fac, String bindDN,
               String bindPW) throws LDAPException;

    /**
     * Retrieves the LDAP connection factory.
     *
     * @return anonymous LDAP connection pool
     */
    public ILdapConnFactory getLdapAnonConnFactory() throws ELdapException;

    /**
     * Retrieves the password check.
     *
     * @return default password checker
     */
    public IPasswordCheck getPasswordChecker();

    /**
     * Puts a password entry into the single-sign on cache.
     *
     * @param tag password tag
     * @param pw password
     */
    public void putPasswordCache(String tag, String pw);

    /**
     * Retrieves the password callback.
     *
     * @return default password callback
     */
    public PasswordCallback getPasswordCallback();

    /**
     * Retrieves the nickname of the server's server certificate.
     *
     * @return nickname of the server certificate
     */
    public String getServerCertNickname();

    /**
     * Sets the nickname of the server's server certificate.
     *
     * @param tokenName name of token where the certificate is located
     * @param nickName name of server certificate
     */
    public void setServerCertNickname(String tokenName, String nickName);

    /**
     * Sets the nickname of the server's server certificate.
     *
     * @param newName new nickname of server certificate
     */
    public void setServerCertNickname(String newName);

    /**
     * Retrieves the host name of the server's secure end entity service.
     *
     * @return host name of end-entity service
     */
    public String getEEHost();

    /**
     * Retrieves the host name of the server's non-secure end entity service.
     *
     * @return host name of end-entity non-secure service
     */
    public String getEENonSSLHost();

    /**
     * Retrieves the IP address of the server's non-secure end entity service.
     *
     * @return ip address of end-entity non-secure service
     */
    public String getEENonSSLIP();

    /**
     * Retrieves the port number of the server's non-secure end entity service.
     *
     * @return port of end-entity non-secure service
     */
    public String getEENonSSLPort();

    /**
     * Retrieves the host name of the server's secure end entity service.
     *
     * @return port of end-entity secure service
     */
    public String getEESSLHost();

    /**
     * Retrieves the IP address of the server's secure end entity service.
     *
     * @return ip address of end-entity secure service
     */
    public String getEESSLIP();

    /**
     * Retrieves the port number of the server's secure end entity service.
     *
     * @return port of end-entity secure service
     */
    public String getEESSLPort();

    /**
     * Retrieves the port number of the server's client auth secure end entity service.
     *
     * @return port of end-entity client auth secure service
     */
    public String getEEClientAuthSSLPort();

    /**
     * Retrieves the host name of the server's agent service.
     *
     * @return host name of agent service
     */
    public String getAgentHost();

    /**
     * Retrieves the IP address of the server's agent service.
     *
     * @return ip address of agent service
     */
    public String getAgentIP();

    /**
     * Retrieves the port number of the server's agent service.
     *
     * @return port of agent service
     */
    public String getAgentPort();

    /**
     * Retrieves the host name of the server's administration service.
     *
     * @return host name of administration service
     */
    public String getAdminHost();

    /**
     * Retrieves the IP address of the server's administration service.
     *
     * @return ip address of administration service
     */
    public String getAdminIP();

    /**
     * Retrieves the port number of the server's administration service.
     *
     * @return port of administration service
     */
    public String getAdminPort();

    /**
     * Verifies all system certificates
     *
     * @return true if all passed, false otherwise
     */
    public boolean verifySystemCerts();

    /**
     * Verifies a system certificate by its tag name
     * as defined in <subsystemtype>.cert.list
     *
     * @return true if passed, false otherwise
     */
    public boolean verifySystemCertByTag(String tag);

    /**
     * Verifies a system certificate by its nickname
     *
     * @return true if passed, false otherwise
     */
    public boolean verifySystemCertByNickname(String nickname, String certificateUsage);

    /**
     * get the CertificateUsage as defined in JSS CryptoManager
     *
     * @return CertificateUsage as defined in JSS CryptoManager
     */
    public CertificateUsage getCertificateUsage(String certusage);

    /**
     * Checks if the given certificate is a signing certificate.
     *
     * @param cert certificate
     * @return true if the given certificate is a signing certificate
     */
    public boolean isSigningCert(X509Certificate cert);

    /**
     * Checks if the given certificate is an encryption certificate.
     *
     * @param cert certificate
     * @return true if the given certificate is an encryption certificate
     */
    public boolean isEncryptionCert(X509Certificate cert);

    /**
     * Retrieves the default X.509 certificate template.
     *
     * @return default certificate template
     */
    public X509CertInfo getDefaultX509CertInfo();

    /**
     * Retrieves the email form processor.
     *
     * @return email form processor
     */
    public IEmailFormProcessor getEmailFormProcessor();

    /**
     * Retrieves the email form template.
     *
     * @return email template
     */
    public IEmailTemplate getEmailTemplate(String path);

    /**
     * Retrieves the email notification handler.
     *
     * @return email notification
     */
    public IMailNotification getMailNotification();

    /**
     * Retrieves the email key resolver.
     *
     * @return email key resolver
     */
    public IEmailResolverKeys getEmailResolverKeys();

    /**
     * Retrieves the email resolver that checks for subjectAlternateName.
     *
     * @return email key resolver
     */
    public IEmailResolver getReqCertSANameEmailResolver();

    /**
     * Checks if the given OID is valid.
     *
     * @param attrName attribute name
     * @param value attribute value
     * @return object identifier of the given attrName
     */
    public ObjectIdentifier checkOID(String attrName, String value)
            throws EBaseException;

    /**
     * Creates a general name constraints.
     *
     * @param generalNameChoice type of general name
     * @param value general name string
     * @return general name object
     * @exception EBaseException failed to create general name constraint
     */
    public GeneralName form_GeneralNameAsConstraints(String generalNameChoice, String value) throws EBaseException;

    /**
     * Creates a general name.
     *
     * @param generalNameChoice type of general name
     * @param value general name string
     * @return general name object
     * @exception EBaseException failed to create general name
     */
    public GeneralName form_GeneralName(String generalNameChoice,
            String value) throws EBaseException;

    /**
     * Retrieves default general name configuration.
     *
     * @param name configuration name
     * @param isValueConfigured true if value is configured
     * @param params configuration parameters
     * @exception EBaseException failed to create subject alt name configuration
     */
    public void getGeneralNameConfigDefaultParams(String name,
            boolean isValueConfigured, Vector<String> params);

    /**
     * Retrieves default general names configuration.
     *
     * @param name configuration name
     * @param isValueConfigured true if value is configured
     * @param params configuration parameters
     * @exception EBaseException failed to create subject alt name configuration
     */
    public void getGeneralNamesConfigDefaultParams(String name,
            boolean isValueConfigured, Vector<String> params);

    /**
     * Retrieves extended plugin info for general name configuration.
     *
     * @param name configuration name
     * @param isValueConfigured true if value is configured
     * @param info configuration parameters
     * @exception EBaseException failed to create subject alt name configuration
     */
    public void getGeneralNameConfigExtendedPluginInfo(String name,
            boolean isValueConfigured, Vector<String> info);

    /**
     * Retrieves extended plugin info for general name configuration.
     *
     * @param name configuration name
     * @param isValueConfigured true if value is configured
     * @param info configuration parameters
     * @exception EBaseException failed to create subject alt name configuration
     */
    public void getGeneralNamesConfigExtendedPluginInfo(String name,
            boolean isValueConfigured, Vector<String> info);

    /**
     * Created general names configuration.
     *
     * @param name configuration name
     * @param config configuration store
     * @param isValueConfigured true if value is configured
     * @param isPolicyEnabled true if policy is enabled
     * @exception EBaseException failed to create subject alt name configuration
     */
    public IGeneralNamesConfig createGeneralNamesConfig(String name,
            IConfigStore config, boolean isValueConfigured,
            boolean isPolicyEnabled) throws EBaseException;

    /**
     * Created general name constraints configuration.
     *
     * @param name configuration name
     * @param config configuration store
     * @param isValueConfigured true if value is configured
     * @param isPolicyEnabled true if policy is enabled
     * @exception EBaseException failed to create subject alt name configuration
     */
    public IGeneralNameAsConstraintsConfig createGeneralNameAsConstraintsConfig(String name, IConfigStore config,
            boolean isValueConfigured,
            boolean isPolicyEnabled) throws EBaseException;

    /**
     * Created general name constraints configuration.
     *
     * @param name configuration name
     * @param config configuration store
     * @param isValueConfigured true if value is configured
     * @param isPolicyEnabled true if policy is enabled
     * @exception EBaseException failed to create subject alt name configuration
     */
    public IGeneralNamesAsConstraintsConfig createGeneralNamesAsConstraintsConfig(String name, IConfigStore config,
            boolean isValueConfigured,
            boolean isPolicyEnabled) throws EBaseException;

    /**
     * Get default parameters for subject alt name configuration.
     *
     * @param name configuration name
     * @param params configuration parameters
     */
    public void getSubjAltNameConfigDefaultParams(String name, Vector<String> params);

    /**
     * Get extended plugin info for subject alt name configuration.
     *
     * @param name configuration name
     * @param params configuration parameters
     */
    public void getSubjAltNameConfigExtendedPluginInfo(String name, Vector<String> params);

    /**
     * Creates subject alt name configuration.
     *
     * @param name configuration name
     * @param config configuration store
     * @param isValueConfigured true if value is configured
     * @exception EBaseException failed to create subject alt name configuration
     */
    public ISubjAltNameConfig createSubjAltNameConfig(String name, IConfigStore config, boolean isValueConfigured)
            throws EBaseException;

    /**
     * Retrieves the HTTP Connection for use with connector.
     *
     * @param authority remote authority
     * @param factory socket factory
     * @return http connection to the remote authority
     */
    public IHttpConnection getHttpConnection(IRemoteAuthority authority,
            ISocketFactory factory);

    /**
     * Retrieves the HTTP Connection for use with connector.
     *
     * @param authority remote authority
     * @param factory socket factory
     * @param timeout return error if connection cannot be established within
     *            the timeout period
     * @return http connection to the remote authority
     */
    public IHttpConnection getHttpConnection(IRemoteAuthority authority,
            ISocketFactory factory, int timeout);

    /**
     * Retrieves the request sender for use with connector.
     *
     * @param authority local authority
     * @param nickname nickname of the client certificate
     * @param remote remote authority
     * @param interval timeout interval
     * @return resender
     */
    public IResender getResender(IAuthority authority, String nickname,
            IRemoteAuthority remote, int interval);

    /**
     * Retrieves command queue
     *
     * @return command queue
     */
    public ICommandQueue getCommandQueue();

    /**
     * Blocks all new incoming requests.
     */
    public void disableRequests();

    /**
     * Terminates all requests that are currently in process.
     */
    public void terminateRequests();

    /**
     * Checks to ensure that all new incoming requests have been blocked.
     * This method is used for reentrancy protection.
     * <P>
     *
     * @return true or false
     */
    public boolean areRequestsDisabled();

    /**
     * Create configuration file.
     *
     * @param path configuration path
     * @return configuration store
     * @exception EBaseException failed to create file
     */
    public IConfigStore createFileConfigStore(String path) throws EBaseException;

    /**
     * Creates argument block.
     */
    public IArgBlock createArgBlock();

    /**
     * Creates argument block.
     */
    public IArgBlock createArgBlock(String realm, Hashtable<String, String> httpReq);

    /**
     * Creates argument block.
     */
    public IArgBlock createArgBlock(Hashtable<String, String> httpReq);

    /**
     * Checks against the local certificate repository to see
     * if the certificates are revoked.
     *
     * @param certificates certificates
     * @return true if certificate is revoked in the local
     *         certificate repository
     */
    public boolean isRevoked(X509Certificate[] certificates);

    /**
     * Sets list of verified certificates
     *
     * @param size size of verified certificates list
     * @param interval interval in which certificate is not recheck
     *            against local certificate repository
     * @param unknownStateInterval interval in which certificate
     *            may not recheck against local certificate repository
     */
    public void setListOfVerifiedCerts(int size, long interval, long unknownStateInterval);

    /**
     * Performs graceful shutdown of CMS.
     * Subsystems are shutdown in reverse order.
     * Exceptions are ignored.
     */
    public void forceShutdown();

    public IPasswordStore getPasswordStore();

    public ISecurityDomainSessionTable getSecurityDomainSessionTable();

    public void setConfigSDSessionId(String id);

    public String getConfigSDSessionId();

    public String getServerStatus();
}
