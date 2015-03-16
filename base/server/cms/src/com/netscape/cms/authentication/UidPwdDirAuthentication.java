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

import netscape.ldap.LDAPAttribute;
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
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileAuthenticator;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.cmsutil.ldap.LDAPUtil;

/**
 * uid/pwd directory based authentication manager
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class UidPwdDirAuthentication extends DirBasedAuthentication
        implements IProfileAuthenticator {

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
        CMS.debug(method + " begins");
        String[] attrs = {};

        String k = null;
        if (mGroupObjectClass.equalsIgnoreCase("groupOfUniqueNames"))
            k = "uniquemember";
        else if (mGroupObjectClass.equalsIgnoreCase("groupOfNames"))
            k = "member";
        else {
            CMS.debug("UidPwdDirAuthentication: isMemberOfLdapGroup: unrecognized mGroupObjectClass: " + mGroupObjectClass);
            return null;
        }

        String filter = null;
        if (mSearchGroupUserByUserdn)
            filter = k + "=" + LDAPUtil.escapeFilter(userdn);
        else
            filter = k + "=" + mGroupUserIDName + "=" + LDAPUtil.escapeFilter(uid);

        CMS.debug(method + "searching " + getGroupBaseDN() + " for (&(objectclass=" + mGroupObjectClass + ")(" + filter + "))");
        LDAPSearchResults res = ldapconn.search(
            getGroupBaseDN(),
            LDAPv2.SCOPE_SUB,
            "(&(objectclass=" + mGroupObjectClass + ")(" + filter + "))",
            attrs, true /* attrsOnly */ );

        CMS.debug(method + " ends");
        return buildGroups(res);
    }

    private ArrayList<String> buildGroups(LDAPSearchResults res) {
        ArrayList<String> v = new ArrayList<>();

        while (res.hasMoreElements()) {
            LDAPEntry entry = (LDAPEntry) res.nextElement();
            String groupDN = entry.getDN();
            CMS.debug("UidPwdDirAuthentication: Authenticate: Found group membership: " + groupDN);
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
    protected String authenticate(LDAPConnection conn,
            IAuthCredentials authCreds,
            AuthToken token)
            throws EBaseException {
        String userdn = null;
        String uid = null;

        // authenticate by binding to ldap server with password.
        try {
            // get the uid.
            uid = (String) authCreds.get(CRED_UID);
            CMS.debug("Authenticating UID=" + uid);
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
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMS_AUTH_EMPTY_PASSWORD", uid));
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }

            /*
             * first try and see if the directory server supports "memberOf"
             * if so, use it, if not, then pull all groups to check
             */
            String emptyAttrs[] = {};
            String groupAttrs[] = {"memberOf"};

            // get user dn.
            CMS.debug("UidPwdDirAuthentication: Authenticating: Searching for " +
                    mUserIDName + "=" + uid + " base DN=" + mBaseDN);
            LDAPSearchResults res = conn.search(
                mBaseDN,
                LDAPv2.SCOPE_SUB,
                "(" + mUserIDName + "=" + LDAPUtil.escapeFilter(uid) + ")",
                (mGroupsEnable ? groupAttrs : emptyAttrs),
                false);

            LDAPEntry entry = null;
            if (res.hasMoreElements()) {
                entry = res.next();

                userdn = entry.getDN();
                CMS.debug("UidPwdDirAuthentication: Authenticating: Found User DN=" + userdn);
            } else {
                log(ILogger.LL_SECURITY, CMS.getLogMessage("CMS_AUTH_USER_NOT_EXIST", uid));
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }

            // bind as user dn and pwd - authenticates user with pwd.
            conn.authenticate(userdn, pwd);

            LDAPAttribute attribute = entry.getAttribute("memberOf");
            if ( attribute != null ) {
                CMS.debug("UidPwdDirAuthentication: Authenticate: Found memberOf attribute");
                String[] groups = attribute.getStringValueArray();
                token.set(IAuthToken.GROUPS, groups);
            } else if (mGroupsEnable) {
                CMS.debug("UidPwdDirAuthentication: Authenticate: memberOf attribute not found.");
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
            CMS.debug("Authenticating: User authentication failure: "+e);
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CANNOT_CONNECT_LDAP", e.toString()));
            throw e;
        } catch (LDAPException e) {
            CMS.debug("Authenticating: User authentication failure: "+e);
            switch (e.getLDAPResultCode()) {
            case LDAPException.NO_SUCH_OBJECT:
            case LDAPException.LDAP_PARTIAL_RESULTS:
                log(ILogger.LL_SECURITY, CMS.getLogMessage("USER_NOT_EXIST", uid));
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));

            case LDAPException.INVALID_CREDENTIALS:
                log(ILogger.LL_SECURITY, CMS.getLogMessage("CMS_AUTH_BAD_PASSWORD", uid));
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));

            case LDAPException.SERVER_DOWN:
                log(ILogger.LL_FAILURE, CMS.getLogMessage("LDAP_SERVER_DOWN"));
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), "" + conn.getPort()));

            default:
                log(ILogger.LL_FAILURE, CMS.getLogMessage("OPERATION_ERROR", e.getMessage()));
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
    public String[] getConfigParams() {
        return (mConfigParams);
    }

    /**
     * Returns array of required credentials for this authentication manager.
     *
     * @return Array of required credentials.
     */
    public String[] getRequiredCreds() {
        return mRequiredCreds;
    }

    // Profile-related methods

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_AUTHENTICATION_LDAP_UID_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_AUTHENTICATION_LDAP_UID_TEXT");
    }

    /**
     * Retrieves a list of names of the value parameter.
     */
    public Enumeration<String> getValueNames() {
        Vector<String> v = new Vector<String>();

        v.addElement(CRED_UID);
        v.addElement(CRED_PWD);
        return v.elements();
    }

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

    public void populate(IAuthToken token, IRequest request)
            throws EProfileException {
        request.setExtData(IProfileAuthenticator.AUTHENTICATED_NAME,
                token.getInString(USER_DN));
    }

    public boolean isSSLClientRequired() {
        return false;
    }
}
