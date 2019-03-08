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
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;

import com.netscape.certsrv.authentication.ISharedToken;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISecurityDomainSessionTable;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.connector.IRemoteAuthority;
import com.netscape.certsrv.connector.IResender;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.notification.IMailNotification;
import com.netscape.certsrv.password.IPasswordCheck;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmsutil.password.IPasswordStore;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSSLSocketFactoryExt;

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
     * Set whether the given subsystem is enabled.
     *
     * @param id The subsystem ID.
     * @param enabled Whether the subsystem is enabled
     */
    public void setSubsystemEnabled(String id, boolean enabled)
        throws EBaseException;

    /**
     * Retrieves the registered subsytem with the given name.
     *
     * @param name subsystem name
     * @return subsystem of the given name
     */
    public ISubsystem getSubsystem(String name);

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
     * Retrieves log message from LogMessages.properties or audit-evenst.properties.
     *
     * @param msgID message ID defined in LogMessages.properties or audit-evenst.properties
     * @param p an array of parameters
     * @return localized log message
     */
    public String getLogMessage(String msgID, Object p[]);

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
     * Retrieves the certifcate in MIME-64 encoded format
     * with header and footer.
     *
     * @param cert certificate
     * @return base-64 format certificate
     */
    public String getEncodedCert(X509Certificate cert);

    public LDAPConnection getBoundConnection(String id, String host, int port,
               int version, LDAPSSLSocketFactoryExt fac, String bindDN,
               String bindPW) throws LDAPException;

    /**
     * Retrieves the named SharedToken class
     *
     * @return named shared token class
     */
    public ISharedToken getSharedTokenClass(String configName);

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
     * Retrieves the email notification handler.
     *
     * @return email notification
     */
    public IMailNotification getMailNotification();

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
            String clientCiphers,
            IRemoteAuthority remote, int interval);

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

    /**
     * graceful shutdown, same as forceShutdown, but allowing
     * option to restart
     */
    public void autoShutdown();
    public void checkForAndAutoShutdown();

    public IPasswordStore getPasswordStore() throws EBaseException;

    public ISecurityDomainSessionTable getSecurityDomainSessionTable();

    public void setConfigSDSessionId(String id);

    public String getConfigSDSessionId();

    public void sleepOneMinute(); // for debug only

    public boolean isExcludedLdapAttrsEnabled();

    public boolean isExcludedLdapAttr(String key);
}
