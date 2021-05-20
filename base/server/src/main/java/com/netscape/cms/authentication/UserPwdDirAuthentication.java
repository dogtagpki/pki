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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.authentication;

// ldap java sdk
import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import org.dogtagpki.server.authentication.AuthManagerConfig;
import org.dogtagpki.server.authentication.AuthToken;

import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
// cert server imports.
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.ProfileAuthenticator;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cmscore.apps.CMS;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;

/**
 * uid/pwd directory based authentication manager
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class UserPwdDirAuthentication extends DirBasedAuthentication
        implements ProfileAuthenticator {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UserPwdDirAuthentication.class);

    /* required credentials to authenticate. uid and pwd are strings. */
    public static final String CRED_UID = "uid";
    public static final String CRED_PWD = "pwd";
    public String mAttr = CRED_UID;

    protected String[] mRequiredCreds = { mAttr, CRED_PWD };

    protected String mAttrName = null;
    protected String mAttrDesc = null;

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
                    "ldap.attrName",
                    "ldap.attrDesc",
                    "ldap.minConns",
                    "ldap.maxConns",
            };

    static {
        mExtendedPluginInfo.add("ldap.attrName;string,required;Attribute name " +
                "like 'cn' or 'uid' allowing to build user's DN by combining " +
                "user name with base DN for  example  'cn=jsmith, o=company'.");
        mExtendedPluginInfo.add("ldap.attrDesc;string,required;Attribute description " +
                "like 'LDAP User CN' or 'LDAP User UID' presented on enrollment page.");
        mExtendedPluginInfo.add(IExtendedPluginInfo.HELP_TEXT +
                ";Authenticate the username and password provided " +
                "by the user against an LDAP directory. Works with the " +
                "Dir Based Enrollment HTML form");
        mExtendedPluginInfo.add(IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-authrules-uidpwddirauth");
    };

    /**
     * Default constructor, initialization must follow.
     */
    public UserPwdDirAuthentication() {
        super();
    }

    /**
     * Initializes the UserPwdDirAuthentication auth manager.
     * <p>
     *
     * @param name - The name for this authentication manager instance.
     * @param implName - The name of the authentication manager plugin.
     * @param config - The configuration store for this instance.
     * @exception EBaseException If an error occurs during initialization.
     */
    @Override
    public void init(String name, String implName, AuthManagerConfig config)
            throws EBaseException {
        super.init(name, implName, config);

        logger.debug("UserPwdDirAuthentication init");
        mAttrName = mLdapConfig.getString("attrName", null);
        if (mAttrName == null || mAttrName.trim().length() == 0) {
            throw new EPropertyNotFound(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED", "attrName"));
        }
        mAttrName = mAttrName.trim();

        mAttrDesc = mLdapConfig.getString("attrDesc", null);
        if (mAttrDesc == null || mAttrDesc.trim().length() == 0) {
            throw new EPropertyNotFound(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED", "attrDesc"));
        }
        mAttrDesc = mAttrDesc.trim();

        if (mAttrName != null && mAttrName.length() > 0) {
            mAttr = mAttrName;
        }
        logger.debug("UserPwdDirAuthentication init  mAttr=" + mAttr +
                "  mAttrName=" + mAttrName + "  mAttrDesc=" + mAttrDesc);
    }

    /**
     * Authenticates a user based on attr, pwd in the directory.
     *
     * @param authCreds The authentication credentials.
     * @return The user's ldap entry dn.
     * @exception EInvalidCredentials If the attr and password are not valid
     * @exception EBaseException If an internal error occurs.
     */
    @Override
    protected String authenticate(LDAPConnection conn,
            IAuthCredentials authCreds,
            AuthToken token)
            throws EBaseException {
        String userdn = null;
        String attr = null;

        // authenticate by binding to ldap server with password.
        try {
            // get the attr.
            attr = (String) authCreds.get(mAttr);
            logger.debug("Authenticating " + mAttr + "=" + attr);
            if (attr == null) {
                throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_NULL_CREDENTIAL", mAttr));
            }

            // get the password.
            String pwd = (String) authCreds.get(CRED_PWD);

            if (pwd == null) {
                throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_NULL_CREDENTIAL", CRED_PWD));
            }
            if (pwd.equals("")) {
                // anonymous binding not allowed
                logger.error("UserPwdDirAuthentication: " + CMS.getLogMessage("CMS_AUTH_EMPTY_PASSWORD", attr));
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }

            // get user dn.
            userdn = mAttr + "=" + attr + "," + mBaseDN;
            logger.debug("Authenticating: userdn=" + userdn);
            // bind as user dn and pwd - authenticates user with pwd.
            conn.authenticate(userdn, pwd);
            logger.debug("Authenticated: userdn=" + userdn);
            // set attr in the token.
            token.set(mAttr, attr);

            return userdn;
        } catch (ELdapException e) {
            logger.error("Authenticating: closing bad connection: " + e.getMessage(), e);
            try {
                conn.disconnect();
            } catch (Exception f) {
                logger.warn("Authenticating: conn.disconnect() exception: " + f.getMessage(), f);
            }
            logger.error("UserPwdDirAuthentication: " + CMS.getLogMessage("CANNOT_CONNECT_LDAP", e.toString()));
            throw e;
        } catch (LDAPException e) {
            logger.error("Authenticating: closing bad connection: " + e.getMessage(), e);
            try {
                conn.disconnect();
            } catch (Exception f) {
                logger.warn("Authenticating: conn.disconnect() exception: " + f.getMessage(), f);
            }
            switch (e.getLDAPResultCode()) {
            case LDAPException.NO_SUCH_OBJECT:
            case LDAPException.LDAP_PARTIAL_RESULTS:
                logger.error("UserPwdDirAuthentication: " + CMS.getLogMessage("USER_NOT_EXIST", attr));
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));

            case LDAPException.INVALID_CREDENTIALS:
                logger.error("UserPwdDirAuthentication: " + CMS.getLogMessage("CMS_AUTH_BAD_PASSWORD", attr));
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));

            case LDAPException.SERVER_DOWN:
                logger.error("UserPwdDirAuthentication: " + CMS.getLogMessage("LDAP_SERVER_DOWN"));
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), "" + conn.getPort()));

            default:
                logger.error("UserPwdDirAuthentication: " + CMS.getLogMessage("OPERATION_ERROR", e.getMessage()));
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
        Vector<String> v = new Vector<>();

        v.addElement(mAttr);
        v.addElement(CRED_PWD);
        return v.elements();
    }

    @Override
    public boolean isValueWriteable(String name) {
        if (name.equals(mAttr)) {
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
        if (name.equals(mAttr)) {
            return new Descriptor(IDescriptor.STRING, null, null,
                    ((mAttrDesc != null && mAttrDesc.length() > 0) ? mAttrDesc :
                            CMS.getUserMessage(locale, "CMS_AUTHENTICATION_LDAP_UID")));
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
