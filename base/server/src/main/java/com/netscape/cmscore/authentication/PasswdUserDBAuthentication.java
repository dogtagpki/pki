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

import java.util.Enumeration;
import java.util.Locale;

import org.dogtagpki.server.authentication.AuthManager;
import org.dogtagpki.server.authentication.AuthManagerConfig;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authentication.AuthenticationConfig;

import com.netscape.certsrv.authentication.AuthCredentials;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.DBException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.ldapconn.LdapAnonConnFactory;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.User;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;

/**
 * Certificate Server admin authentication.
 * Used to authenticate administrators in the Certificate Server Console.
 * Authentications by checking the uid and password against the
 * database.
 *
 * @author lhsiao, cfu
 */
public class PasswdUserDBAuthentication extends AuthManager {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PasswdUserDBAuthentication.class);

    /* required credentials. uid, pwd are strings */
    public static final String CRED_UID = "uid";
    public static final String CRED_PWD = "pwd";

    /* attribute in returned token */
    public static final String TOKEN_USERDN = "userdn";
    public static final String TOKEN_USERID = "userid";

    /* required credentials. uid, pwd are strings */
    protected static String[] mRequiredCred = { CRED_UID, CRED_PWD };

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
    @Override
    public void init(
            AuthenticationConfig authenticationConfig,
            String name, String implName, AuthManagerConfig config)
            throws EBaseException {
        this.authenticationConfig = authenticationConfig;
        mName = name;
        mImplName = implName;
        mConfig = config;

        DBSubsystem dbSubsystem = engine.getDBSubsystem();
        LdapConnInfo ldapinfo = dbSubsystem.getLdapConnInfo();

        mAnonConnFactory = engine.createLdapAnonConnFactory("PasswdUserDBAuthentication", 0, 20, ldapinfo);
    }

    @Override
    public void init(ConfigStore config) throws EProfileException {
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
    @Override
    public AuthToken authenticate(AuthCredentials authCred)
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

        UGSubsystem ug = engine.getUGSubsystem();
        User user;

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

    @Override
    public void populate(AuthToken token, Request request) throws EProfileException {
    }

    @Override
    public String getText(Locale locale) {
        return null;
    }

    @Override
    public Enumeration<String> getValueNames() {
        return null;
    }

    @Override
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        return null;
    }

    @Override
    public boolean isValueWriteable(String name) {
        return false;
    }

    @Override
    public boolean isSSLClientRequired() {
        return false;
    }

    /**
     * get the list of authentication credential attribute names
     * required by this authentication manager. Generally used by
     * servlets that use this authentication manager, to retrieve
     * required credentials from the user (e.g. Javascript form data)
     *
     * @return attribute names in Vector
     */
    @Override
    public String[] getRequiredCreds() {
        return mRequiredCred;
    }

    /**
     * disconnects the member connection
     */
    @Override
    public void shutdown() {
        try {
            // disconnect all outstanding connections in the factory
            if (mAnonConnFactory != null) mAnonConnFactory.reset();
        } catch (DBException e) {
            logger.error("Unable to disconnect LDAP connections: " + e.getMessage(), e);
        }
    }
}
