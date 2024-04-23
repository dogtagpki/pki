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
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;

import org.dogtagpki.server.authentication.AuthManager;
import org.dogtagpki.server.authentication.AuthManagerConfig;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authentication.AuthenticationConfig;

import com.netscape.certsrv.authentication.AuthCredentials;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.dbs.DBException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
// cert server x509 imports
// java sdk imports.
import com.netscape.cmscore.apps.CMS;
// cert server imports.
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.User;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchResults;

/**
 * uid/pwd directory based authentication manager
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class UserPwdDirAuthentication extends DirBasedAuthentication {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UserPwdDirAuthentication.class);
    /* required credentials to authenticate. uid and pwd are strings. */
    public String mAttr = CRED_UID;
    protected String[] mRequiredCreds = { mAttr, CRED_PWD };

    protected String mAttrName = null;
    protected String mAttrDesc = null;
    protected String mMemberAttrName = null;
    protected String mMemberAttrValue = null;
    protected String mInternalGroup = null;
    protected boolean mInternalUserRequired = false;
    protected UGSubsystem mUGS = null;
    protected String mAttrs[] = null;

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
                    "ldap.memberAttrName",
                    "ldap.memberAttrValue",
                    "ldap.internalUserRequired",
                    "ldap.internalGroup",
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
    public void init(
            AuthenticationConfig authenticationConfig,
            String name, String implName, AuthManagerConfig config)
            throws EBaseException {
        super.init(authenticationConfig, name, implName, config);

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

        // Optional attribute, which presence and value have to be checked if included in configuration
        mMemberAttrName = mLdapConfig.getString("memberAttrName", null);
        mMemberAttrName = (mMemberAttrName != null)? mMemberAttrName.trim(): mMemberAttrName;
        if (mMemberAttrName != null && mMemberAttrName.length() > 0) {
            mMemberAttrValue = mLdapConfig.getString("memberAttrValue", null);
            mMemberAttrValue = (mMemberAttrValue != null)? mMemberAttrValue.trim(): mMemberAttrValue;
            logger.debug("UserPwdDirAuthentication init  mMemberAttrName=" + mMemberAttrName + "  mMemberAttrValue=" + mMemberAttrValue);
        }
        // Optional attribute, which indicates local user entry presence that have to be checked if included in configuration
        mInternalUserRequired = mLdapConfig.getBoolean("internalUserRequired", false);
        logger.debug("UserPwdDirAuthentication init  mInternalUserRequired=" + mInternalUserRequired);
        mInternalGroup = mLdapConfig.getString("internalGroup", null);
        mInternalGroup = (mInternalGroup != null)? mInternalGroup.trim(): mInternalGroup;
        if (mInternalGroup != null && mInternalGroup.length() > 0) {
            mInternalUserRequired = true;
            logger.debug("UserPwdDirAuthentication init  mInternalGroup=" + mInternalGroup);
        }
        if (mInternalUserRequired) {
            mUGS = engine.getUGSubsystem();
        }

        ArrayList<String> attrList = new ArrayList<>();
        if (mInternalUserRequired) {
            attrList.add(CRED_UID);
        }
        if (mMemberAttrName != null && mMemberAttrName.length() > 0 && !mMemberAttrName.equalsIgnoreCase(CRED_UID)) {
            attrList.add(mMemberAttrName);
        }
        mAttrs = attrList.toArray(new String[attrList.size()]);
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
            AuthCredentials authCreds,
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

            LDAPEntry entry = null;
            Map<String, String[]> entryAttributes = new HashMap<>();
            if (mAttrs != null && mAttrs.length > 0) {
                LDAPSearchResults results = conn.search(userdn, LDAPConnection.SCOPE_BASE, null, mAttrs, false);
                if (results != null && results.hasMoreElements()) {
                    entry = results.next();
                    if (entry != null) {
                        logger.debug("Reviewing entry: " + entry.getDN());
                        for (int i = 0; i < mAttrs.length; i++) {
                            LDAPAttribute memberAttribute = entry.getAttribute(mAttrs[i]);
                            if (memberAttribute != null) {
                                String[] values = memberAttribute.getStringValueArray();
                                if (values != null && values.length > 0) {
                                    entryAttributes.put(mAttrs[i], values);
                                }
                            }
                        }
                    }
                }
            }
            if (mAttrs != null && mAttrs.length > 0 && (entry == null || entryAttributes.size() == 0)) {
                logger.debug("Failed to obtain data required for verification.");
                throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }

            if (mMemberAttrName != null && mMemberAttrName.length() > 0) {
                logger.debug("Authenticating: memberAttribute=" + mMemberAttrName);
                String[] values = entryAttributes.get(mMemberAttrName);
                boolean verified = false;
                if (values != null && values.length > 0) {
                    if (mMemberAttrValue != null && mMemberAttrValue.length() > 0) {
                        for (int i = 0; i < values.length; i++) {
                            if (mMemberAttrValue.equalsIgnoreCase(values[i])) {
                                verified = true;
                            }
                        }
                    } else {
                        verified = true;
                    }
                }
                if (!verified) {
                    logger.debug("Failed to verify memberAttribute");
                    throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
                }

                if (mInternalUserRequired) {
                    values = entryAttributes.get(CRED_UID);
                    verified = false;
                    if (values != null && values.length > 0) {
                        for (int i = 0; i < values.length; i++) {
                            User user = mUGS.getUser(values[i]);
                            if (user != null) {
                                if (mInternalGroup != null && mInternalGroup.length() > 0) {
                                    if (mUGS.isMemberOf(values[i], mInternalGroup)) {
                                        verified = true;
                                        logger.debug("Authenticated: user='" + user.getUserDN() + "' is member of '" + mInternalGroup + "'");
                                    }
                                } else {
                                    verified = true;
                                    logger.debug("Authenticated: user='" + user.getUserDN() + "'");
                                }
                            }
                        }
                    }
                    if (!verified) {
                        logger.debug("Failed to verify userAttribute");
                        throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
                    }
                }

            } else {
                if (mInternalUserRequired) {
                    String userAttr = (mAttr.equalsIgnoreCase(CRED_UID))? attr: entryAttributes.get(CRED_UID)[0];
                    if (userAttr != null  && userAttr.length() > 0) {
                        logger.debug("Authenticating: InternalUser: '" + CRED_UID + "=" + userAttr + "'");
                        User user = mUGS.getUser(userAttr);
                        if (user != null) {
                            if (mInternalGroup != null && mInternalGroup.length() > 0) {
                                if (mUGS.isMemberOf(userAttr, mInternalGroup)) {
                                    logger.debug("Authenticated: user='" + user.getUserDN() + "' is member of '" + mInternalGroup + "'");
                                } else {
                                    logger.debug("Authenticated: user='" + user.getUserDN() + "' is NOT member of '" + mInternalGroup + "'");
                                    throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
                                }
                            } else {
                                logger.debug("Authenticated: user='" + user.getUserDN() + "'");
                            }
                        } else {
                            logger.debug("Missing InternalUser='" + userAttr + "'");
                            throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
                        }
                    } else {
                        logger.debug("Incorrect attribute requested: '" + mAttr + "' instead of '" + CRED_UID + "'");
                        throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
                    }
                }
            }

            // set attr in the token.
            token.set(mAttr, attr);

            return userdn;

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
                throw new DBException(
                        CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), "" + conn.getPort()));

            default:
                logger.error("UserPwdDirAuthentication: " + CMS.getLogMessage("OPERATION_ERROR", e.getMessage()));
                throw new DBException(
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
    public void init(ConfigStore config)
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
    public void populate(AuthToken token, Request request)
            throws EProfileException {
        request.setExtData(AuthManager.AUTHENTICATED_NAME,
                token.getInString(USER_DN));
    }

    @Override
    public boolean isSSLClientRequired() {
        return false;
    }
}
