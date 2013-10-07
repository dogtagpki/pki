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
package com.netscape.cms.authorization;

import java.util.Enumeration;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPModificationSet;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;

import com.netscape.certsrv.acls.ACL;
import com.netscape.certsrv.acls.EACLsException;
import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.authorization.EAuthzInternalError;
import com.netscape.certsrv.authorization.IAuthzManager;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.certsrv.logging.ILogger;

/**
 * A class for ldap acls based authorization manager
 * The ldap server used for acls is the cms internal ldap db.
 *
 * @version $Revision$, $Date$
 */
public class DirAclAuthz extends AAclAuthz
        implements IAuthzManager, IExtendedPluginInfo {

    // members

    /* name of this authentication manager instance */
    private String mName = null;

    /* name of the authentication manager plugin */
    private String mImplName = null;

    /* configuration store */
    private IConfigStore mConfig;

    /* the system logger */
    private ILogger mLogger = null;

    protected static final String PROP_BASEDN = "basedn";

    private ILdapConnFactory mLdapConnFactory = null;
    private String mBaseDN = null;
    private static boolean needsFlush = false;

    static {
        mExtendedPluginInfo.add("ldap.ldapconn.host;string,required;" +
                "LDAP host to connect to");
        mExtendedPluginInfo.add("ldap.ldapconn.port;number,required;" +
                "LDAP port number (use 389, or 636 if SSL)");
        mExtendedPluginInfo.add("ldap.ldapconn.secureConn;boolean;" +
                "Use SSL to connect to directory?");
        mExtendedPluginInfo.add("ldap.ldapconn.version;choice(3,2);" +
                "LDAP protocol version");
        mExtendedPluginInfo.add("ldap.basedn;string,required;Base DN to start sarching " +
                "under. If the ACL's DN is 'cn=resourceACL, o=NetscapeCertificateServer' you " +
                "might want to use 'o=NetscapeCertificateServer' here");
        mExtendedPluginInfo.add("ldap.minConns;number;number of connections " +
                "to keep open to directory server. Default 5.");
        mExtendedPluginInfo.add("ldap.maxConns;number;when needed, connection "
                +
                "pool can grow to this many (multiplexed) connections. Default 1000");
    }

    /**
     * Default constructor
     */
    public DirAclAuthz() {

        /* Holds configuration parameters accepted by this implementation.
         * This list is passed to the configuration console so configuration
         * for instances of this implementation can be configured through the
         * console.
         */
        mConfigParams =
                new String[] {
                        "ldap.ldapconn.host",
                        "ldap.ldapconn.port",
                        "ldap.ldapconn.secureConn",
                        "ldap.ldapconn.version",
                        "ldap.basedn",
                        "ldap.minConns",
                        "ldap.maxConns",
                };
    }

    /**
     *
     */
    public void init(String name, String implName, IConfigStore config)
            throws EBaseException {
        mName = name;
        mImplName = implName;
        mConfig = config;
        mLogger = CMS.getLogger();

        super.init(config);

        // initialize LDAP connection factory
        IConfigStore ldapConfig = mConfig.getSubStore("ldap");

        if (ldapConfig == null) {
            log(ILogger.LL_MISCONF, "failed to get config ldap info");
            return;
        }

        mBaseDN = ldapConfig.getString(PROP_BASEDN, null);

        try {
            @SuppressWarnings("unused")
            String hostname = ldapConfig.getString("ldapconn.host"); // check for errors
        } catch (EBaseException e) {
            if (CMS.isPreOpMode())
                return;
        }

        mLdapConnFactory = CMS.getLdapBoundConnFactory();
        mLdapConnFactory.init(ldapConfig);

        // retrieve aclResources from the LDAP server and load
        // into memory
        LDAPConnection conn = null;

        CMS.debug("DirAclAuthz: about to ldap search aclResources");
        try {
            conn = getConn();
            LDAPSearchResults res = conn.search(mBaseDN, LDAPv2.SCOPE_SUB,
                    "cn=aclResources", null, false);

            returnConn(conn);
            if (res.hasMoreElements()) {
                log(ILogger.LL_INFO, "ldap search found cn=aclResources");

                LDAPEntry entry = (LDAPEntry) res.nextElement();
                LDAPAttribute aclRes = entry.getAttribute("resourceACLS");

                @SuppressWarnings("unchecked")
                Enumeration<String> en = aclRes.getStringValues();

                for (; en != null && en.hasMoreElements();) {
                    addACLs(en.nextElement());
                }
            } else {
                log(ILogger.LL_INFO, "ldap search found no cn=aclResources");
            }
        } catch (LDAPException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("AUTHZ_EVALUATOR_INIT_ERROR", e.toString()));
            throw new EACLsException(CMS.getUserMessage("CMS_ACL_CONNECT_LDAP_FAIL", mBaseDN));
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("AUTHZ_EVALUATOR_INIT_ERROR", e.toString()));
        }

        log(ILogger.LL_INFO, "initialization done");
    }

    /**
     * gets the name of this authorization manager instance
     */
    public String getName() {
        return mName;
    }

    /**
     * gets the plugin name of this authorization manager.
     */
    public String getImplName() {
        return mImplName;
    }

    /**
     * check the authorization permission for the user associated with
     * authToken on operation
     * <p>
     * Example:
     * <p>
     * For example, if UsrGrpAdminServlet needs to authorize the caller it would do be done in the following fashion:
     *
     * <PRE>
     * try {
     *     authzTok = mAuthz.authorize(&quot;DirAclAuthz&quot;, authToken, RES_GROUP, &quot;read&quot;);
     * } catch (EBaseException e) {
     *     log(ILogger.LL_FAILURE, &quot;authorize call: &quot; + e.toString());
     * }
     * </PRE>
     *
     * @param authToken the authToken associated with a user
     * @param resource - the protected resource name
     * @param operation - the protected resource operation name
     * @exception EBaseException If an internal error occurred.
     * @return authzToken
     */
    public AuthzToken authorize(IAuthToken authToken, String resource, String operation)
            throws EAuthzInternalError, EAuthzAccessDenied {
        AuthzToken authzToken = new AuthzToken(this);

        try {
            checkPermission(authToken, resource, operation);
            // compose AuthzToken
            authzToken.set(AuthzToken.TOKEN_AUTHZ_RESOURCE, resource);
            authzToken.set(AuthzToken.TOKEN_AUTHZ_OPERATION, operation);
            authzToken.set(AuthzToken.TOKEN_AUTHZ_STATUS, AuthzToken.AUTHZ_STATUS_SUCCESS);
            CMS.debug("DirAclAuthz: authorization passed");
        } catch (EACLsException e) {
            // audit here later
            log(ILogger.LL_FAILURE, CMS.getLogMessage("AUTHZ_EVALUATOR_AUTHORIZATION_FAILED"));
            String params[] = { resource, operation };

            throw new EAuthzAccessDenied(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZ_ACCESS_DENIED", params));
        }

        return authzToken;
    }

    public AuthzToken authorize(IAuthToken authToken, String expression)
            throws EAuthzAccessDenied {
        if (evaluateACLs(authToken, expression)) {
            return (new AuthzToken(this));
        } else {
            String params[] = { expression };
            throw new EAuthzAccessDenied(CMS.getUserMessage("CMS_AUTHORIZATION_AUTHZ_ACCESS_DENIED", params));
        }
    }

    /**
     * update acls. when memory update is done, flush to ldap.
     * <p>
     * Currently, it is possible that when the memory is updated successfully, and the ldap isn't, the memory upates
     * lingers. The result is that the changes will only be done on ldap at the next update, or when the system shuts
     * down, another flush will be attempted.
     *
     * @param id is the resource id
     * @param rights The allowable rights for this resource
     * @param strACLs has the same format as a resourceACLs entry acis
     *            on the ldap server
     * @param desc The description for this resource
     */
    public void updateACLs(String id, String rights, String strACLs,
            String desc) throws EACLsException {
        try {
            super.updateACLs(id, rights, strACLs, desc);
            flushResourceACLs();
            needsFlush = false;
        } catch (EACLsException ex) {
            // flushing failed, set flag
            needsFlush = true;

            log(ILogger.LL_FAILURE, CMS.getLogMessage("AUTHZ_EVALUATOR_FLUSH_RESOURCES", ex.toString()));

            throw new EACLsException(CMS.getUserMessage("CMS_ACL_UPDATE_FAIL"));
        }
    }

    /**
     * updates resourceACLs to ldap.
     */
    protected void flushResourceACLs() throws EACLsException {
        // ldap update
        LDAPConnection conn = null;

        try {
            LDAPAttribute attrs = new LDAPAttribute("resourceACLS");
            LDAPModificationSet mod = new LDAPModificationSet();

            Enumeration<ACL> en = aclResElements();

            if (en.hasMoreElements() == true) {
                while (en.hasMoreElements()) {
                    ACL a = en.nextElement();
                    String resAclString = a.getResourceACLs();

                    attrs.addValue(resAclString);
                }

                mod.add(LDAPModification.REPLACE, attrs);

                conn = getConn();
                conn.modify("cn=aclResources," + mBaseDN, mod);
            }
        } catch (LDAPException ex) {
            System.out.println(ex.toString());
            throw new EACLsException(CMS.getUserMessage("CMS_ACL_UPDATE_FAIL"));
        } catch (Exception ex) {
            System.out.println(ex.toString());
            throw new EACLsException(CMS.getUserMessage("CMS_ACL_UPDATE_FAIL"));
        } finally {
            try {
                returnConn(conn);
            } catch (ELdapException e) {
                log(ILogger.LL_FAILURE, "couldn't return conn ?");
            }
        }
    }

    protected LDAPConnection getConn() throws ELdapException {
        return mLdapConnFactory.getConn();
    }

    protected void returnConn(LDAPConnection conn) throws ELdapException {
        mLdapConnFactory.returnConn(conn);
    }

    /**
     * graceful shutdown
     */
    public void shutdown() {
        if (needsFlush) {
            // flush the changes
            try {
                flushResourceACLs();
            } catch (EACLsException e) {
                // flushing failed again...too bad
                log(ILogger.LL_FAILURE, CMS.getLogMessage("AUTHZ_EVALUATOR_FLUSH_ERROR", e.toString()));
            }
        }

        try {
            if (mLdapConnFactory != null) mLdapConnFactory.reset();
        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("AUTHZ_EVALUATOR_LDAP_ERROR", e.toString()));
        }
    }

    /**
     * Logs a message for this class in the system log file.
     *
     * @param level The log level.
     * @param msg The message to log.
     * @see com.netscape.certsrv.logging.ILogger
     */
    protected void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_AUTHORIZATION,
                level, msg);
    }
}
