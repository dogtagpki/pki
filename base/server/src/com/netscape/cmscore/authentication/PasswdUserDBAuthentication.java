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
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.ldapconn.LdapAnonConnFactory;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.usrgrp.UGSubsystem;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;

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

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PasswdUserDBAuthentication.class);

    /* required credentials. uid, pwd are strings */
    protected static String[] mRequiredCred = { CRED_UID, CRED_PWD };

    /* configuration params to pass to console (none) */
    protected static String[] mConfigParams = null;

    private String mName = null;
    private String mImplName = null;
    private IConfigStore mConfig;
    private LdapAnonConnFactory mAnonConnFactory = null;

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

        CMSEngine engine = CMS.getCMSEngine();
        IConfigStore cs = engine.getConfigStore();

        /* internal database directory used */
        DBSubsystem dbs = (DBSubsystem) DBSubsystem.getInstance();
        LdapConnInfo ldapinfo = dbs.getLdapConnInfo();

        mAnonConnFactory = new LdapAnonConnFactory("PasswdUserDBAuthentication", 3, 20, ldapinfo);
        mAnonConnFactory.init(cs);

        logger.info(CMS.getLogMessage("CMSCORE_AUTH_INIT_AUTH", mName));
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
        logger.info("PasswdUserDBAuthentication: authenticating UID: " + uid);

        if (uid == null) {
            logger.error(CMS.getLogMessage("CMSCORE_AUTH_MISSING_UID"));
            throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_NULL_CREDENTIAL", CRED_UID));
        }

        String pwd = (String) authCred.get(CRED_PWD);
        if (pwd == null) {
            logger.error(CMS.getLogMessage("CMSCORE_AUTH_ADMIN_NULL_PW", uid));
            throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_NULL_CREDENTIAL", CRED_PWD));
        }

        // don't allow anonymous binding
        if (pwd.equals("")) {
            logger.error(CMS.getLogMessage("CMSCORE_AUTH_ADMIN_EMPTY_PW", uid));
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        }

        UGSubsystem ug = UGSubsystem.getInstance();
        IUser user;

        try {
            user = ug.getUser(uid);
        } catch (EBaseException e) {
            logger.error("Unable to authenticate user: " + e.getMessage(), e);
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL") + " " + e.getMessage(), e);
        }

        if (user == null) {
            logger.error("PasswdUserDBAuthentication: User not found: " + uid);
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INTERNAL_ERROR",
                    "Failure in User Group subsystem."));
        }

        String userdn = user.getUserDN();
        logger.info("PasswdUserDBAuthentication: DN: " + userdn);

        LDAPConnection anonConn = null;

        try {
            anonConn = mAnonConnFactory.getConn();
            anonConn.authenticate(userdn, pwd);

        } catch (LDAPException e) {
            logger.error(CMS.getLogMessage("CMSCORE_AUTH_AUTH_FAILED", uid, e.toString()), e);
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"), e);

        } finally {
            if (anonConn != null)
                mAnonConnFactory.returnConn(anonConn);
        }

        authToken.set(TOKEN_USERDN, userdn);
        authToken.set(CRED_UID, uid); // return original uid for info

        authToken.set(TOKEN_USERDN, user.getUserDN());
        authToken.set(TOKEN_USERID, user.getUserID());

        logger.info(CMS.getLogMessage("CMS_AUTH_AUTHENTICATED", uid));

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
        return mRequiredCred;
    }

    /**
     * Get the list of configuration parameter names
     * required by this authentication manager. In this case, an empty list.
     *
     * @return String array of configuration parameters.
     */
    public String[] getConfigParams() {
        return mConfigParams;
    }

    /**
     * disconnects the member connection
     */
    public void shutdown() {
        try {
            // disconnect all outstanding connections in the factory
            if (mAnonConnFactory != null) mAnonConnFactory.reset();
        } catch (ELdapException e) {
            logger.error("Unable to disconnect LDAP connections: " + e.getMessage(), e);
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
}
