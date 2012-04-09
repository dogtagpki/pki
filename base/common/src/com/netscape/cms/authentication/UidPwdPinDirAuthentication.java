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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileAuthenticator;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;

/**
 * uid/pwd/pin directory based authentication manager
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class UidPwdPinDirAuthentication extends DirBasedAuthentication
        implements IExtendedPluginInfo, IProfileAuthenticator {

    /* required credentials to authenticate. uid and pwd are strings. */
    public static final String CRED_UID = "uid";
    public static final String CRED_PWD = "pwd";
    public static final String CRED_PIN = "pin";
    protected static String[] mRequiredCreds = { CRED_UID, CRED_PWD, CRED_PIN };

    public static final String PROP_REMOVE_PIN = "removePin";
    public static final String PROP_PIN_ATTR = "pinAttr";

    public static final boolean DEF_REMOVE_PIN = false;
    public static final String DEF_PIN_ATTR = "pin";

    protected static final byte SENTINEL_SHA = 0;
    protected static final byte SENTINEL_MD5 = 1;
    protected static final byte SENTINEL_NONE = 0x2d;

    /* Holds configuration parameters accepted by this implementation.
     * This list is passed to the configuration console so configuration
     * for instances of this implementation can be configured through the
     * console.
     */
    protected static String[] mConfigParams =
            new String[] { PROP_REMOVE_PIN,
                    PROP_PIN_ATTR,
                    PROP_DNPATTERN,
                    PROP_LDAPSTRINGATTRS,
                    PROP_LDAPBYTEATTRS,
                    "ldap.ldapconn.host",
                    "ldap.ldapconn.port",
                    "ldap.ldapconn.secureConn",
                    "ldap.ldapconn.version",
                    "ldap.ldapauth.bindDN",
                    "ldap.ldapauth.bindPWPrompt",
                    "ldap.ldapauth.clientCertNickname",
                    "ldap.ldapauth.authtype",
                    "ldap.basedn",
                    "ldap.minConns",
                    "ldap.maxConns",
        };

    static {
        mExtendedPluginInfo.add(
                PROP_REMOVE_PIN + ";boolean;SEE DOCUMENTATION for pin removal");
        mExtendedPluginInfo.add(
                PROP_PIN_ATTR + ";string;directory attribute to use for pin (default 'pin')");
        mExtendedPluginInfo.add(
                "ldap.ldapauth.bindDN;string;DN to bind as for pin removal. "
                        + "For example 'CN=PinRemoval User'");
        mExtendedPluginInfo.add(
                "ldap.ldapauth.bindPWPrompt;password;Enter password used to bind as " +
                        "the above user");
        mExtendedPluginInfo.add(
                "ldap.ldapauth.clientCertNickname;string;If you want to use "
                        + "SSL client auth to the directory, set the client "
                        + "cert nickname here");
        mExtendedPluginInfo.add(
                "ldap.ldapauth.authtype;choice(BasicAuth,SslClientAuth),required;"
                        + "How to bind to the directory (for pin removal only)");
        mExtendedPluginInfo.add(IExtendedPluginInfo.HELP_TEXT
                + ";Authenticate the username, password and pin provided "
                + "by the user against an LDAP directory. Works with the "
                + "Dir/Pin Based Enrollment HTML form");
        mExtendedPluginInfo.add(IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-authrules-uidpwdpindirauth");

    }

    protected boolean mRemovePin = DEF_REMOVE_PIN;
    protected String mPinAttr = DEF_PIN_ATTR;
    protected MessageDigest mSHADigest = null;
    protected MessageDigest mMD5Digest = null;

    private ILdapConnFactory removePinLdapFactory = null;
    private LDAPConnection removePinLdapConnection = null;
    private IConfigStore removePinLdapConfigStore = null;

    /**
     * Default constructor, initialization must follow.
     */
    public UidPwdPinDirAuthentication() {
        super();
    }

    public void init(String name, String implName, IConfigStore config)
            throws EBaseException {
        super.init(name, implName, config);
        mRemovePin =
                config.getBoolean(PROP_REMOVE_PIN, DEF_REMOVE_PIN);
        mPinAttr =
                config.getString(PROP_PIN_ATTR, DEF_PIN_ATTR);
        if (mPinAttr.equals("")) {
            mPinAttr = DEF_PIN_ATTR;
        }

        if (mRemovePin) {
            removePinLdapConfigStore = config.getSubStore("ldap");
            removePinLdapFactory = CMS.getLdapBoundConnFactory();
            removePinLdapFactory.init(removePinLdapConfigStore);
            removePinLdapConnection = removePinLdapFactory.getConn();
        }

        try {
            mSHADigest = MessageDigest.getInstance("SHA1");
            mMD5Digest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new EAuthException(CMS.getUserMessage("CMS_AUTHENTICATION_INTERNAL_ERROR", e.getMessage()));
        }

    }

    protected void verifyPassword(String Password) {
    }

    /**
     * Authenticates a user based on its uid, pwd, pin in the directory.
     *
     * @param authCreds The authentication credentials with uid, pwd, pin.
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
        String pwd = null;
        String pin = null;

        try {
            // get the uid.
            uid = (String) authCreds.get(CRED_UID);
            if (uid == null) {
                throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_NULL_CREDENTIAL", CRED_UID));
            }

            // get the password.
            pwd = (String) authCreds.get(CRED_PWD);
            if (pwd == null) {
                throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_NULL_CREDENTIAL", CRED_PWD));
            }
            if (pwd.equals("")) {
                // anonymous binding not allowed
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMS_AUTH_EMPTY_PASSWORD", uid));
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }

            // get the pin.
            pin = (String) authCreds.get(CRED_PIN);
            if (pin == null) {
                throw new EMissingCredential(CMS.getUserMessage("CMS_AUTHENTICATION_NULL_CREDENTIAL", CRED_PIN));
            }
            if (pin.equals("")) {
                // empty pin not allowed
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMS_AUTH_EMPTY_PIN", uid));
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }

            // get user dn.
            LDAPSearchResults res = conn.search(mBaseDN,
                    LDAPv2.SCOPE_SUB, "(uid=" + uid + ")", null, false);

            if (res.hasMoreElements()) {
                LDAPEntry entry = (LDAPEntry) res.nextElement();

                userdn = entry.getDN();
            } else {
                log(ILogger.LL_SECURITY, CMS.getLogMessage("CMS_AUTH_USER_NOT_EXIST", uid));
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }

            // bind as user dn and pwd - authenticates user with pwd.
            conn.authenticate(userdn, pwd);

            log(ILogger.LL_SECURITY, CMS.getLogMessage("CMS_AUTH_AUTHENTICATED", uid));
            // log(ILogger.LL_SECURITY, "found user : " + userdn);

            // check pin.
            checkpin(conn, userdn, uid, pin);

            // set uid in the token.
            token.set(CRED_UID, uid);

            return userdn;
        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CANNOT_CONNECT_LDAP", e.toString()));
            throw e;
        } catch (LDAPException e) {
            switch (e.getLDAPResultCode()) {
            case LDAPException.NO_SUCH_OBJECT:
            case LDAPException.LDAP_PARTIAL_RESULTS:
                log(ILogger.LL_SECURITY, CMS.getLogMessage("CMS_AUTH_USER_NOT_EXIST", uid));
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));

            case LDAPException.INVALID_CREDENTIALS:
                log(ILogger.LL_SECURITY, CMS.getLogMessage("CMS_AUTH_BAD_PASSWORD", uid));
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));

            case LDAPException.SERVER_DOWN:
                log(ILogger.LL_SECURITY, CMS.getLogMessage("LDAP_SERVER_DOWN"));
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

    protected void checkpin(LDAPConnection conn, String userdn,
            String uid, String pin)
            throws EBaseException, LDAPException {
        LDAPSearchResults res = null;
        LDAPEntry entry = null;

        // get pin.

        res = conn.search(userdn, LDAPv2.SCOPE_BASE,
                    "(objectclass=*)", new String[] { mPinAttr }, false);
        if (res.hasMoreElements()) {
            entry = (LDAPEntry) res.nextElement();
        } else {
            log(ILogger.LL_SECURITY, CMS.getLogMessage("CMS_AUTH_NO_ENTRY_RETURNED", uid, userdn));
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        }

        LDAPAttribute pinAttr = entry.getAttribute(mPinAttr);

        if (pinAttr == null) {
            log(ILogger.LL_SECURITY, CMS.getLogMessage("CMS_AUTH_NO_PIN_FOUND", uid));
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        }

        @SuppressWarnings("unchecked")
        Enumeration<byte[]> pinValues = pinAttr.getByteValues();

        if (!pinValues.hasMoreElements()) {
            log(ILogger.LL_SECURITY, CMS.getLogMessage("CMS_AUTH_NO_PIN_FOUND", uid));
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        }
        byte[] entrypin = pinValues.nextElement();

        // compare value digest.

        if (entrypin == null || entrypin.length < 2) {
            log(ILogger.LL_SECURITY, CMS.getLogMessage("CMS_AUTH_NO_PIN_FOUND", uid));
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        }

        byte hashtype = entrypin[0];

        byte[] pinDigest = null;
        String toBeDigested = userdn + pin;

        if (hashtype == SENTINEL_SHA) {

            pinDigest = mSHADigest.digest(toBeDigested.getBytes());
        } else if (hashtype == SENTINEL_MD5) {
            pinDigest = mMD5Digest.digest(toBeDigested.getBytes());
        } else if (hashtype == SENTINEL_NONE) {
            pinDigest = toBeDigested.getBytes();
        } else {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMS_AUTH_UKNOWN_ENCODING_TYPE", mPinAttr, "*", userdn));
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        }

        if (pinDigest.length != (entrypin.length - 1)) {
            log(ILogger.LL_SECURITY, CMS.getLogMessage("CMS_AUTH_LENGTH_NOT_MATCHED", uid));
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        }

        int i;

        for (i = 0; i < (entrypin.length - 1); i++) {
            if (pinDigest[i] != entrypin[i + 1])
                break;
        }
        if (i != (entrypin.length - 1)) {
            log(ILogger.LL_SECURITY, CMS.getLogMessage("CMS_AUTH_BAD_PASSWORD", uid));
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        }

        // pin ok. remove pin if so configured
        // Note that this means that a policy may reject this request later,
        // but the user will not be able to enroll again as his pin is gone.

        // We remove the pin using a different connection which is bound as
        // a more privileged user.

        if (mRemovePin) {

            try {
                removePinLdapConnection.modify(userdn,
                        new LDAPModification(
                                LDAPModification.DELETE,
                                new LDAPAttribute(mPinAttr, entrypin)));

            } catch (LDAPException e) {
                log(ILogger.LL_SECURITY, CMS.getLogMessage("CMS_AUTH_CANT_REMOVE_PIN", userdn));
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
        return CMS.getUserMessage(locale, "CMS_AUTHENTICATION_LDAP_UID_PIN_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_AUTHENTICATION_LDAP_UID_PIN_TEXT");
    }

    /**
     * Retrieves a list of names of the value parameter.
     */
    public Enumeration<String> getValueNames() {
        Vector<String> v = new Vector<String>();

        v.addElement(CRED_UID);
        v.addElement(CRED_PWD);
        v.addElement(CRED_PIN);
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
        } else if (name.equals(CRED_PIN)) {
            return new Descriptor(IDescriptor.PASSWORD, null, null,
                    CMS.getUserMessage(locale, "CMS_AUTHENTICATION_LDAP_PIN"));

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
