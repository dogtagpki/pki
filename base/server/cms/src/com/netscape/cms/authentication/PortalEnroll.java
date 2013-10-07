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
import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPObjectClassSchema;
import netscape.ldap.LDAPSchema;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.EAuthInternalError;
import com.netscape.certsrv.authentication.EAuthUserError;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.certsrv.logging.ILogger;

/**
 * uid/pwd directory based authentication manager
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class PortalEnroll extends DirBasedAuthentication {

    /* configuration parameter keys */
    protected static final String PROP_LDAPAUTH = "ldapauth";
    protected static final String PROP_AUTHTYPE = "authtype";
    protected static final String PROP_BINDDN = "bindDN";
    protected static final String PROP_BINDPW = "bindPW";
    protected static final String PROP_LDAPCONN = "ldapconn";
    protected static final String PROP_HOST = "host";
    protected static final String PROP_PORT = "port";
    protected static final String PROP_SECURECONN = "secureConn";
    protected static final String PROP_VERSION = "version";
    protected static final String PROP_OBJECTCLASS = "objectclass";

    /* required credentials to authenticate. uid and pwd are strings. */
    public static final String CRED_UID = "uid";
    public static final String CRED_PWD = "userPassword";
    protected static String[] mRequiredCreds = { CRED_UID, CRED_PWD };

    /* ldap configuration sub-store */
    private IArgBlock argblk = null;
    private String mObjectClass = null;
    private String mBindDN = null;
    private String mBaseDN = null;
    private ILdapConnFactory mLdapFactory = null;
    private LDAPConnection mLdapConn = null;

    // contains all nested superiors' required attrs in the form of a
    //	vector of "required" attributes in Enumeration
    Vector<Enumeration<String>> mRequiredAttrs = null;

    // contains all nested superiors' optional attrs in the form of a
    //	vector of "optional" attributes in Enumeration
    Vector<Enumeration<String>> mOptionalAttrs = null;

    // contains all the objclasses, including superiors and itself
    Vector<String> mObjClasses = null;

    /* Holds configuration parameters accepted by this implementation.
     * This list is passed to the configuration console so configuration
     * for instances of this implementation can be configured through the
     * console.
     */
    protected static String[] mConfigParams =
            new String[] {
                    PROP_DNPATTERN,
                    "ldap.ldapconn.host",
                    "ldap.ldapconn.port",
                    "ldap.ldapconn.secureConn",
                    "ldap.ldapconn.version",
                    "ldap.ldapauth.bindDN",
                    "ldap.ldapauth.bindPWPrompt",
                    "ldap.ldapauth.clientCertNickname",
                    "ldap.ldapauth.authtype",
                    "ldap.basedn",
                    "ldap.objectclass",
                    "ldap.minConns",
                    "ldap.maxConns",
        };

    /**
     * Default constructor, initialization must follow.
     */
    public PortalEnroll()
            throws EBaseException {
        super();
    }

    /**
     * Initializes the PortalEnrollment auth manager.
     * <p>
     *
     * @param name - The name for this authentication manager instance.
     * @param implName - The name of the authentication manager plugin.
     * @param config - The configuration store for this instance.
     * @exception EBaseException If an error occurs during initialization.
     */
    public void init(String name, String implName, IConfigStore config)
            throws EBaseException {
        super.init(name, implName, config);

        /* Get Bind DN for directory server */
        mConfig = mLdapConfig.getSubStore(PROP_LDAPAUTH);
        mBindDN = mConfig.getString(PROP_BINDDN);
        if ((mBindDN == null) || (mBindDN.length() == 0) || (mBindDN == ""))
            throw new EPropertyNotFound(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED", "binddn"));

        /* Get Bind DN for directory server */
        mBaseDN = mLdapConfig.getString(PROP_BASEDN);
        if ((mBaseDN == null) || (mBaseDN.length() == 0) || (mBaseDN == ""))
            throw new EPropertyNotFound(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED", "basedn"));

        /* Get Object clase name for enrollment */
        mObjectClass = mLdapConfig.getString(PROP_OBJECTCLASS);
        if (mObjectClass == null || mObjectClass.length() == 0)
            throw new EPropertyNotFound(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED", "objectclass"));

        /* Get connect parameter */
        mLdapFactory = CMS.getLdapBoundConnFactory();
        mLdapFactory.init(mLdapConfig);
        mLdapConn = mLdapFactory.getConn();

        log(ILogger.LL_INFO, CMS.getLogMessage("CMS_AUTH_PORTAL_INIT"));
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
        String uid = null;
        String pwd = null;
        String dn = null;

        argblk = authCreds.getArgBlock();

        // authenticate by binding to ldap server with password.
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
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }

            // get user dn.
            LDAPSearchResults res = conn.search(mBaseDN,
                    LDAPv2.SCOPE_SUB, "(uid=" + uid + ")", null, false);

            if (res.hasMoreElements()) {
                res.nextElement(); // consume the entry

                throw new EAuthUserError(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_ATTRIBUTE_VALUE",
                        "UID already exists."));
            } else {
                dn = regist(token, uid);
                if (dn == null)
                    throw new EAuthUserError(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_ATTRIBUTE_VALUE",
                            "Could not add user " + uid + "."));
            }

            // bind as user dn and pwd - authenticates user with pwd.
            conn.authenticate(dn, pwd);

            // set uid in the token.
            token.set(CRED_UID, uid);

            log(ILogger.LL_INFO, "portal authentication is done");

            return dn;
        } catch (ELdapException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("LDAP_ERROR", e.toString()));
            throw e;
        } catch (LDAPException e) {
            switch (e.getLDAPResultCode()) {
            case LDAPException.NO_SUCH_OBJECT:
            case LDAPException.LDAP_PARTIAL_RESULTS:
                log(ILogger.LL_SECURITY,
                        CMS.getLogMessage("CMS_AUTH_ADD_USER_ERROR", conn.getHost(), Integer.toString(conn.getPort())));
                throw new EAuthInternalError(CMS.getUserMessage("CMS_AUTHENTICATION_INTERNAL_ERROR",
                        "Check Configuration detail."));

            case LDAPException.INVALID_CREDENTIALS:
                log(ILogger.LL_SECURITY,
                        CMS.getLogMessage("CMS_AUTH_BAD_PASSWORD", uid));
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));

            case LDAPException.SERVER_DOWN:
                log(ILogger.LL_FAILURE, CMS.getLogMessage("LDAP_SERVER_DOWN"));
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), "" + conn.getPort()));

            default:
                log(ILogger.LL_FAILURE, CMS.getLogMessage("LDAP_ERROR", e.getMessage()));
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_OTHER_LDAP_EXCEPTION",
                                e.errorCodeToString()));
            }
        } catch (EBaseException e) {
            if (e.getMessage().equalsIgnoreCase(CMS.getUserMessage("CMS_BASE_ATTRIBUTE_NOT_FOUND")) == true)
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMS_AUTH_MAKE_DN_ERROR", e.toString()));
            throw e;
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

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] s = {
                PROP_DNPATTERN + ";string;Template for cert" +
                        " Subject Name. ($dn.xxx - get value from user's LDAP " +
                        "DN.  $attr.yyy - get value from LDAP attributes in " +
                        "user's entry.) Default: " + DEFAULT_DNPATTERN,
                "ldap.ldapconn.host;string,required;" + "LDAP host to connect to",
                "ldap.ldapconn.port;number,required;" + "LDAP port number (default 389, or 636 if SSL)",
                "ldap.objectclass;string,required;SEE DOCUMENTATION for Object Class. "
                        + "Default is inetOrgPerson.",
                "ldap.ldapconn.secureConn;boolean;" + "Use SSL to connect to directory?",
                "ldap.ldapconn.version;choice(3,2);" + "LDAP protocol version",
                "ldap.ldapauth.bindDN;string,required;DN to bind as for Directory Manager. "
                        + "For example 'CN=Directory Manager'",
                "ldap.ldapauth.bindPWPrompt;password;Enter password used to bind as " +
                        "the above user",
                "ldap.ldapauth.authtype;choice(BasicAuth,SslClientAuth);"
                        + "How to bind to the directory (for pin removal only)",
                "ldap.ldapauth.clientCertNickname;string;If you want to use "
                        + "SSL client auth to the directory, set the client "
                        + "cert nickname here",
                "ldap.basedn;string,required;Base DN to start searching " +
                        "under. If your user's DN is 'uid=jsmith, o=company', you " +
                        "might want to use 'o=company' here",
                "ldap.minConns;number;number of connections " +
                        "to keep open to directory server",
                "ldap.maxConns;number;when needed, connection " +
                        "pool can grow to this many connections",
                IExtendedPluginInfo.HELP_TEXT +
                        ";This authentication plugin checks to see if a user " +
                        "exists in the directory. If not, then the user is created " +
                        "with the requested password.",
                IExtendedPluginInfo.HELP_TOKEN + ";configuration-authrules-portalauth"
            };

        return s;
    }

    /**
     * Returns array of required credentials for this authentication manager.
     *
     * @return Array of required credentials.
     */
    public String[] getRequiredCreds() {
        return mRequiredCreds;
    }

    /**
     * adds a user to the directory.
     *
     * @return dn upon success and null upon failure.
     * @param token authentication token
     * @param uid the user's id.
     */
    public String regist(AuthToken token, String uid) {
        String dn = "uid=" + uid + "," + mBaseDN;

        /* Specify the attributes of the entry */
        Vector<String> objectclass_values = null;

        LDAPAttributeSet attrs = new LDAPAttributeSet();
        LDAPAttribute attr = new LDAPAttribute("objectclass");

        // initialized to new
        mRequiredAttrs = new Vector<Enumeration<String>>();
        mOptionalAttrs = new Vector<Enumeration<String>>();
        mObjClasses = new Vector<String>();

        LDAPSchema dirSchema = null;

        try {

            /* Construct a new LDAPSchema object to hold
             the schema that you want to retrieve. */
            dirSchema = new LDAPSchema();

            /* Get the schema from the Directory. Anonymous access okay. */
            dirSchema.fetchSchema(mLdapConn);
        } catch (LDAPException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("LDAP_ERROR", e.getMessage()));
        }
        // complete mRequiredAttrs, mOptionalAttrs, and mObjClasses
        initLdapAttrs(dirSchema, mObjectClass);

        objectclass_values = mObjClasses;
        for (int i = objectclass_values.size() - 1; i >= 0; i--)
            attr.addValue(objectclass_values.elementAt(i));
        attrs.add(attr);

        Enumeration<Enumeration<String>> objClasses = mRequiredAttrs.elements();
        Enumeration<String> attrnames = null;

        while (objClasses.hasMoreElements()) {
            attrnames = objClasses.nextElement();
            CMS.debug("PortalEnroll: Required attrs:");
            while (attrnames.hasMoreElements()) {
                String attrname = attrnames.nextElement();
                String attrval = null;

                CMS.debug("PortalEnroll: attrname is: " + attrname);
                if (attrname.equalsIgnoreCase("objectclass") == true)
                    continue;
                try {
                    attrval = argblk.getValueAsString(attrname);
                } catch (EBaseException e) {
                    if (e.getMessage().equalsIgnoreCase(CMS.getUserMessage("CMS_BASE_ATTRIBUTE_NOT_FOUND")) == true)
                        continue;
                }

                CMS.debug("PortalEnroll: " + attrname + " = " + attrval);
                attrs.add(new LDAPAttribute(attrname, attrval));
            }

        }

        objClasses = mOptionalAttrs.elements();
        attrnames = null;

        while (objClasses.hasMoreElements()) {
            attrnames = objClasses.nextElement();
            CMS.debug("PortalEnroll: Optional attrs:");
            while (attrnames.hasMoreElements()) {
                String attrname = attrnames.nextElement();
                String attrval = null;

                CMS.debug("PortalEnroll: attrname is: " + attrname);
                try {
                    attrval = argblk.getValueAsString(attrname);
                } catch (EBaseException e) {
                    if (e.getMessage().equalsIgnoreCase(CMS.getUserMessage("CMS_BASE_ATTRIBUTE_NOT_FOUND")) == true)
                        continue;
                }
                CMS.debug("PortalEnroll: " + attrname + " = " + attrval);
                if (attrval != null) {
                    attrs.add(new LDAPAttribute(attrname, attrval));
                }
            }
        }

        /* Create an entry with this DN and these attributes */
        LDAPEntry entry = new LDAPEntry(dn, attrs);

        try {

            /* Now add the entry to the directory */
            mLdapConn.add(entry);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("LDAP_ERROR", e.getMessage()));
            } else
                log(ILogger.LL_FAILURE, CMS.getLogMessage("LDAP_ERROR", e.getMessage()));
            return null;
        }

        log(ILogger.LL_INFO, CMS.getLogMessage("CMS_AUTH_REGISTRATION_DONE"));

        return dn;
    }

    /*
     *  get the superiors of "inetOrgPerson" so the "required
     *  attributes", "optional qttributes", and "object classes" are complete;
     *  should build up
     *  mRequiredAttrs, mOptionalAttrs, and mObjClasses when returned
     */
    @SuppressWarnings("unchecked")
    public void initLdapAttrs(LDAPSchema dirSchema, String oclass) {
        CMS.debug("PortalEnroll: in initLdapAttrsAttrs");
        mObjClasses.addElement(oclass);
        if (oclass.equalsIgnoreCase("top"))
            return;

        try {

            /* Get and print the def. of the object class. */
            LDAPObjectClassSchema objClass = dirSchema.getObjectClass(oclass);

            if (objClass != null) {
                mRequiredAttrs.add(objClass.getRequiredAttributes());
                mOptionalAttrs.add(objClass.getOptionalAttributes());
            } else {
                return;
            }

            CMS.debug("PortalEnroll: getting superiors for: " + oclass);
            String superiors[] = objClass.getSuperiors();

            CMS.debug("PortalEnroll: got superiors, superiors.length=" + superiors.length);
            if (superiors.length == 0)
                return;
            for (int i = 0; i < superiors.length; i++) {
                CMS.debug("Portalenroll: superior" + i + "=" + superiors[i]);
                objClass = dirSchema.getObjectClass(superiors[i]);
                initLdapAttrs(dirSchema, superiors[i]);
            }
        } catch (Exception e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("LDAP_ERROR", e.getMessage()));
        }
    }
}
