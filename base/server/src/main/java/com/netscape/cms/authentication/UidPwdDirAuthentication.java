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
package com.netscape.cms.authentication;

// ldap java sdk
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import org.dogtagpki.server.authentication.AuthToken;

import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.cms.profile.ProfileAuthenticator;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmsutil.ldap.LDAPUtil;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;

/**
 * uid/pwd directory based authentication manager
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class UidPwdDirAuthentication extends DirBasedAuthentication
        implements ProfileAuthenticator {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UidPwdDirAuthentication.class);

    /* required credentials to authenticate. uid and pwd are strings. */
    public static final String CRED_UID = "uid";
    public static final String CRED_PWD = "pwd";
    protected static String[] mRequiredCreds = { CRED_UID, CRED_PWD };

    /* Holds configuration parameters accepted by this implementation.
     * This list is passed to the configuration console so configuration
     * for instances of this implementation can be configured through the
     * console.
     */
    protected static String[] mConfigParams =
            new String[] { PROP_DNPATTERN,
                    PROP_LDAPSTRINGATTRS,
                    PROP_LDAPBYTEATTRS,
                    "ldap.ldapconn.host",
                    "ldap.ldapconn.port",
                    "ldap.ldapconn.secureConn",
                    "ldap.ldapconn.version",
                    "ldap.basedn",
                    "ldap.minConns",
                    "ldap.maxConns",
        };

    static {
        mExtendedPluginInfo.add(IExtendedPluginInfo.HELP_TEXT +
                ";Authenticate the username and password provided " +
                "by the user against an LDAP directory. Works with the " +
                "Dir Based Enrollment HTML form");
        mExtendedPluginInfo.add(IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-authrules-uidpwddirauth");
    };

    /**
     * Retrieves group base dn.
     */
    private String getGroupBaseDN() {
        return mGroups + "," + mGroupsBaseDN;
    }

    /**
     * List groups of which user is a member.
     */
    private ArrayList<String> listGroups(LDAPConnection ldapconn, String uid, String userdn)
            throws EUsrGrpException, LDAPException {
        String method = "UidPwdDirAuthentication: listGroups: ";
        logger.debug(method + " begins");
        String[] attrs = {};

        String k = null;
        if (mGroupObjectClass.equalsIgnoreCase("groupOfUniqueNames"))
            k = "uniquemember";
        else if (mGroupObjectClass.equalsIgnoreCase("groupOfNames"))
            k = "member";
        else {
            logger.warn("UidPwdDirAuthentication: isMemberOfLdapGroup: unrecognized mGroupObjectClass: " + mGroupObjectClass);
            return null;
        }

        String filter = null;
        if (mSearchGroupUserByUserdn)
            filter = k + "=" + LDAPUtil.escapeFilter(userdn);
        else
            filter = k + "=" + mGroupUserIDName + "=" + LDAPUtil.escapeFilter(uid);

        logger.debug(method + "searching " + getGroupBaseDN() + " for (&(objectclass=" + mGroupObjectClass + ")(" + filter + "))");
        LDAPSearchResults res = ldapconn.search(
            getGroupBaseDN(),
            LDAPv2.SCOPE_SUB,
            "(&(objectclass=" + mGroupObjectClass + ")(" + filter + "))",
            attrs, true /* attrsOnly */ );

        logger.debug(method + " ends");
        return buildGroups(res);
    }

    private ArrayList<String> buildGroups(LDAPSearchResults res) {
        ArrayList<String> v = new ArrayList<>();

        while (res.hasMoreElements()) {
            LDAPEntry entry = (LDAPEntry) res.nextElement();
            String groupDN = entry.getDN();
            logger.debug("UidPwdDirAuthentication: Authenticate: Found group membership: " + groupDN);
            v.add(groupDN);
        }
        return v;
    }

    /**
     * Authenticates a user based on uid, pwd in the directory.
     *
     * @param authCreds The authentication credentials.
     * @return The user's ldap entry dn.
     * @exception EInvalidCredentials If the uid and password are not valid
     * @exception EBaseException If an internal error occurs.
     */
    @Override
    protected String authenticate(LDAPConnection conn,
            IAuthCredentials authCreds,
            AuthToken token)
            throws EBaseException {

        String uid = null;

        // authenticate by binding to ldap server with password.
        try {
            // get the uid.
            uid = (String) authCreds.get(CRED_UID);
            logger.info("Authenticating UID " + uid);

            if (uid == null) {
                throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_NULL_CREDENTIAL", CRED_UID));
            }

            // get the password.
            String pwd = (String) authCreds.get(CRED_PWD);

            if (pwd == null) {
                throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_NULL_CREDENTIAL", CRED_PWD));
            }

            if (pwd.equals("")) {
                // anonymous binding not allowed
                logger.error("UidPwdDirAuthentication: " + CMS.getLogMessage("CMS_AUTH_EMPTY_PASSWORD", uid));
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }

            /*
             * first try and see if the directory server supports "memberOf"
             * if so, use it, if not, then pull all groups to check
             */
            String emptyAttrs[] = {};
            String groupAttrs[] = {"memberOf"};

            // get user dn.
            logger.info("UidPwdDirAuthentication: Searching for user " + uid);

            logger.info("UidPwdDirAuthentication: - base DN: " + mBaseDN);

            String filter = "(" + mUserIDName + "=" + LDAPUtil.escapeFilter(uid) + ")";
            logger.info("UidPwdDirAuthentication: - filter: " + filter);

            String[] attrs = mGroupsEnable ? groupAttrs : emptyAttrs;
            logger.info("DirBasedAuthentication: - attributes:");
            for (String attr : attrs) {
                logger.info("DirBasedAuthentication:   - " + attr);
            }

            LDAPSearchResults results = conn.search(
                    mBaseDN,
                    LDAPv2.SCOPE_SUB,
                    filter,
                    attrs,
                    false);

            if (!results.hasMoreElements()) {
                logger.error("UidPwdDirAuthentication: " + CMS.getLogMessage("CMS_AUTH_USER_NOT_EXIST", uid));
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }

            LDAPEntry entry = results.next();
            String userdn = entry.getDN();
            logger.debug("UidPwdDirAuthentication: Found user " + userdn);

            // bind as user dn and pwd - authenticates user with pwd.
            conn.authenticate(userdn, pwd);

            LDAPAttribute attribute = entry.getAttribute("memberOf");

            if (attribute != null) {
                logger.debug("UidPwdDirAuthentication: Authenticate: Found memberOf attribute");
                String[] groups = attribute.getStringValueArray();
                token.set(IAuthToken.GROUPS, groups);

            } else if (mGroupsEnable) {
                logger.debug("UidPwdDirAuthentication: Authenticate: memberOf attribute not found.");
                ArrayList<String> groups = null;
                groups = listGroups(conn, uid, userdn);
                if (groups != null) {
                    String[] groupsArray = new String[groups.size()];
                    token.set(IAuthToken.GROUPS, groups.toArray(groupsArray));
                }
            }

            // set uid in the token.
            token.set(IAuthToken.UID, uid);
            token.set(IAuthToken.USER_ID, uid);

            return userdn;

        } catch (ELdapException e) {
            logger.error("Authenticating: User authentication failure: " + e.getMessage(), e);
            logger.debug("Authenticating: closing bad connection");
            try {
                conn.disconnect();
            } catch (Exception f) {
                logger.warn("Authenticating: conn.disconnect() exception: " + f.getMessage(), f);
            }
            logger.error("UidPwdDirAuthentication: " + CMS.getLogMessage("CANNOT_CONNECT_LDAP", e.toString()));
            throw e;

        } catch (LDAPException e) {
            logger.error("Authenticating: User authentication failure: " + e.getMessage(), e);
            logger.debug("Authenticating: closing bad connection");
            try {
                conn.disconnect();
            } catch (Exception f) {
                logger.warn("Authenticating: conn.disconnect() exception =" + f.getMessage(), e);
            }
            switch (e.getLDAPResultCode()) {
            case LDAPException.NO_SUCH_OBJECT:
            case LDAPException.LDAP_PARTIAL_RESULTS:
                logger.error("UidPwdDirAuthentication: " + CMS.getLogMessage("USER_NOT_EXIST", uid));
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));

            case LDAPException.INVALID_CREDENTIALS:
                logger.error("UidPwdDirAuthentication: " + CMS.getLogMessage("CMS_AUTH_BAD_PASSWORD", uid));
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));

            case LDAPException.SERVER_DOWN:
                logger.error("UidPwdDirAuthentication: " + CMS.getLogMessage("LDAP_SERVER_DOWN"));
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), "" + conn.getPort()));

            default:
                logger.error("UidPwdDirAuthentication: " + CMS.getLogMessage("OPERATION_ERROR", e.getMessage()));
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_OTHER_LDAP_EXCEPTION",
                                e.errorCodeToString()));
            }
        }
    }

    /**
     * Returns a list of configuration parameter names.
     * The list is passed to the configuration console so instances of
     * this implementation can be configured through the console.
     *
     * @return String array of configuration parameter names.
     */
    @Override
    public String[] getConfigParams() {
        return (mConfigParams);
    }

    /**
     * Returns array of required credentials for this authentication manager.
     *
     * @return Array of required credentials.
     */
    @Override
    public String[] getRequiredCreds() {
        return mRequiredCreds;
    }

    // Profile-related methods

    @Override
    public void init(Profile profile, IConfigStore config)
            throws EProfileException {
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    @Override
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_AUTHENTICATION_LDAP_UID_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    @Override
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_AUTHENTICATION_LDAP_UID_TEXT");
    }

    /**
     * Retrieves a list of names of the value parameter.
     */
    @Override
    public Enumeration<String> getValueNames() {
        Vector<String> v = new Vector<String>();

        v.addElement(CRED_UID);
        v.addElement(CRED_PWD);
        return v.elements();
    }

    @Override
    public boolean isValueWriteable(String name) {
        if (name.equals(CRED_UID)) {
            return true;
        } else if (name.equals(CRED_PWD)) {
            return false;
        }
        return false;
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
    @Override
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(CRED_UID)) {
            return new Descriptor(IDescriptor.STRING, null, null,
                    CMS.getUserMessage(locale, "CMS_AUTHENTICATION_LDAP_UID"));
        } else if (name.equals(CRED_PWD)) {
            return new Descriptor(IDescriptor.PASSWORD, null, null,
                    CMS.getUserMessage(locale, "CMS_AUTHENTICATION_LDAP_PWD"));

        }
        return null;
    }

    @Override
    public void populate(IAuthToken token, IRequest request)
            throws EProfileException {
        request.setExtData(ProfileAuthenticator.AUTHENTICATED_NAME,
                token.getInString(USER_DN));
    }

    @Override
    public boolean isSSLClientRequired() {
        return false;
    }
}
