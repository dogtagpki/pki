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
package com.netscape.cmscore.authentication;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authentication.IPasswdUserDBAuthentication;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.ldapconn.LdapAnonConnFactory;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.util.Debug;

/**
 * Certificate Server admin authentication.
 * Used to authenticate administrators in the Certificate Server Console.
 * Authentications by checking the uid and password against the
 * database.
 * <P>
 *
 * @author lhsiao, cfu
 * @version $Revision$, $Date$
 */
public class PasswdUserDBAuthentication implements IAuthManager, IPasswdUserDBAuthentication {

    /* required credentials. uid, pwd are strings */
    protected static String[] mRequiredCred = { CRED_UID, CRED_PWD };

    /* configuration params to pass to console (none) */
    protected static String[] mConfigParams = null;

    private String mName = null;
    private String mImplName = null;
    private IConfigStore mConfig;
    private String mBaseDN = null;
    private LdapBoundConnFactory mConnFactory = null;
    private LdapAnonConnFactory mAnonConnFactory = null;
    private ILogger mLogger = CMS.getLogger();

    public PasswdUserDBAuthentication() {
    }

    /**
     * initializes the PasswdUserDBAuthentication auth manager
     * <p>
     * called by AuthSubsystem init() method, when initializing all available authentication managers.
     *
     * @param name - Name assigned to this authentication manager instance.
     * @param implName - Name of the authentication plugin.
     * @param config - The configuration store used by the
     *            authentication subsystem.
     */
    public void init(String name, String implName, IConfigStore config)
            throws EBaseException {
        mName = name;
        mImplName = implName;
        mConfig = config;

        /* internal database directory used */
        DBSubsystem dbs = (DBSubsystem) DBSubsystem.getInstance();
        LdapConnInfo ldapinfo = dbs.getLdapConnInfo();
        if (ldapinfo == null && CMS.isPreOpMode())
            return;

        mBaseDN = dbs.getBaseDN();
        mConnFactory = new LdapBoundConnFactory(3, 20, ldapinfo, dbs.getLdapAuthInfo());
        mAnonConnFactory = new LdapAnonConnFactory(3, 20, ldapinfo);

        log(ILogger.LL_INFO, CMS.getLogMessage("CMSCORE_AUTH_INIT_AUTH", mName));
    }

    /**
     * authenticates administratrators by LDAP uid/pwd
     * <p>
     * called by other subsystems or their servlets to authenticate administrators
     *
     * @param authCred Authentication credentials.
     *            "uid" and "pwd" are required.
     * @return the authentication token (authToken) that contains the following
     *         userdn = [userdn, in case of success]<br>
     *         authMgrName = [authMgrName]<br>
     * @exception com.netscape.certsrv.base.MissingCredential If either
     *                "uid" or "pwd" is missing from the given credentials.
     * @exception com.netscape.certsrv.base.InvalidCredentials If the
     *                the credentials failed to authenticate.
     * @exception com.netscape.certsrv.base.EBaseException If an internal
     *                error occurred.
     */
    public IAuthToken authenticate(IAuthCredentials authCred)
            throws EMissingCredential, EInvalidCredentials, EBaseException {
        AuthToken authToken = new AuthToken(this);

        // make sure the required credentials are provided
        String uid = (String) authCred.get(CRED_UID);
        CMS.debug("Authentication: UID=" + uid);
        if (uid == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_AUTH_MISSING_UID"));
            throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_NULL_CREDENTIAL", CRED_UID));
        }
        String pwd = (String) authCred.get(CRED_PWD);

        if (pwd == null) {
            log(ILogger.LL_SECURITY, CMS.getLogMessage("CMSCORE_AUTH_ADMIN_NULL_PW", uid));
            throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_NULL_CREDENTIAL", CRED_PWD));
        }
        // don't allow anonymous binding
        if (pwd == "") {
            log(ILogger.LL_SECURITY, CMS.getLogMessage("CMSCORE_AUTH_ADMIN_EMPTY_PW", uid));
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        }

        String userdn = null;
        LDAPConnection conn = null;
        LDAPConnection anonConn = null;

        try {
            conn = mConnFactory.getConn();
            // do anonymous search for the user's dn.
            LDAPSearchResults res = conn.search(mBaseDN,
                    LDAPv2.SCOPE_SUB, "(uid=" + uid + ")", null, false);

            if (res.hasMoreElements()) {
                LDAPEntry entry = (LDAPEntry) res.nextElement();

                userdn = entry.getDN();
            }
            if (userdn == null) {
                log(ILogger.LL_SECURITY, CMS.getLogMessage("CMSCORE_AUTH_ADMIN_NOT_FOUND", uid));
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }
            anonConn = mAnonConnFactory.getConn();
            anonConn.authenticate(userdn, pwd);
        } catch (LDAPException e) {
            log(ILogger.LL_SECURITY, CMS.getLogMessage("CMSCORE_AUTH_AUTH_FAILED", uid, e.toString()));
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        } finally {
            if (conn != null)
                mConnFactory.returnConn(conn);
            if (anonConn != null)
                mAnonConnFactory.returnConn(anonConn);
        }

        UGSubsystem ug = UGSubsystem.getInstance();

        authToken.set(TOKEN_USERDN, userdn);
        authToken.set(CRED_UID, uid); // return original uid for info

        IUser user = null;

        try {
            user = ug.getUser(uid);
        } catch (EBaseException e) {
            if (Debug.ON)
                e.printStackTrace();
            // not a user in our user/group database.
            log(ILogger.LL_SECURITY, CMS.getLogMessage("CMSCORE_AUTH_UID_NOT_FOUND", uid, e.toString()));
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL") + " " + e.getMessage());
        }
        if (user == null) {
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INTERNAL_ERROR",
                    "Failure in User Group subsystem."));
        }
        authToken.set(TOKEN_USERDN, user.getUserDN());
        authToken.set(TOKEN_USERID, user.getUserID());
        log(ILogger.LL_INFO, CMS.getLogMessage("CMS_AUTH_AUTHENTICATED", uid));

        return authToken;
    }

    /**
     * gets the name of this authentication manager instance
     */
    public String getName() {
        return mName;
    }

    /**
     * gets the name of the authentication manager plugin
     */
    public String getImplName() {
        return mImplName;
    }

    /**
     * get the list of authentication credential attribute names
     * required by this authentication manager. Generally used by
     * servlets that use this authentication manager, to retrieve
     * required credentials from the user (e.g. Javascript form data)
     *
     * @return attribute names in Vector
     */
    public String[] getRequiredCreds() {
        return (mRequiredCred);
    }

    /**
     * Get the list of configuration parameter names
     * required by this authentication manager. In this case, an empty list.
     *
     * @return String array of configuration parameters.
     */
    public String[] getConfigParams() {
        return (mConfigParams);
    }

    /**
     * disconnects the member connection
     */
    public void shutdown() {
        try {
            // disconnect all outstanding connections in the factory
            if (mConnFactory != null) mConnFactory.reset();
        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE, e.toString());
        }
    }

    /**
     * gets the configuretion substore used by this authentication
     * manager
     *
     * @return configuration store
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * Log a message.
     *
     * @param level The logging level.
     * @param msg The message to log.
     */
    private void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_AUTHENTICATION,
                level, msg);
    }
}
