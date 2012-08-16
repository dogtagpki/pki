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
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;
import java.util.StringTokenizer;
import java.util.Vector;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.CertificateValidity;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.authentication.EFormSubjectDN;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cmsutil.util.Utils;

/**
 * Abstract class for directory based authentication managers
 * Uses a pattern for formulating subject names.
 * The pattern is read from configuration file.
 * Syntax of the pattern is described in the init() method.
 *
 * <P>
 *
 * @version $Revision$, $Date$
 */
public abstract class DirBasedAuthentication
        implements IAuthManager, IExtendedPluginInfo {

    protected static final String USER_DN = "userDN";

    /* configuration parameter keys */
    protected static final String PROP_LDAP = "ldap";
    protected static final String PROP_BASEDN = "basedn";
    protected static final String PROP_DNPATTERN = "dnpattern";
    protected static final String PROP_LDAPSTRINGATTRS = "ldapStringAttributes";
    protected static final String PROP_LDAPBYTEATTRS = "ldapByteAttributes";

    // members

    /* name of this authentication manager instance */
    protected String mName = null;

    /* name of the authentication manager plugin */
    protected String mImplName = null;

    /* configuration store */
    protected IConfigStore mConfig;

    /* ldap configuration sub-store */
    protected IConfigStore mLdapConfig;

    /* ldap base dn */
    protected String mBaseDN = null;

    /* factory of anonymous ldap connections */
    protected ILdapConnFactory mConnFactory = null;

    /* the system logger */
    protected ILogger mLogger = CMS.getLogger();

    /* the subject DN pattern */
    protected DNPattern mPattern = null;

    /* the list of LDAP attributes with string values to retrieve to
     * save in the auth token including ones from the dn pattern. */
    protected String[] mLdapStringAttrs = null;

    /* the list of LDAP attributes with byte[] values to retrive to save
     * in authtoken. */
    protected String[] mLdapByteAttrs = null;

    /* the combined list of LDAP attriubutes to retrieve*/
    protected String[] mLdapAttrs = null;

    /* default dn pattern if left blank or not set in the config */
    protected static String DEFAULT_DNPATTERN =
            "E=$attr.mail, CN=$attr.cn, O=$dn.o, C=$dn.c";

    /* Vector of extendedPluginInfo strings */
    protected static Vector<String> mExtendedPluginInfo = null;

    static {
        mExtendedPluginInfo = new Vector<String>();
        mExtendedPluginInfo.add(PROP_DNPATTERN + ";string;Template for cert" +
                " Subject Name. ($dn.xxx - get value from user's LDAP " +
                "DN.  $attr.yyy - get value from LDAP attributes in " +
                "user's entry.) Default: " + DEFAULT_DNPATTERN);
        mExtendedPluginInfo.add(PROP_LDAPSTRINGATTRS + ";string;" +
                "Comma-separated list of LDAP attributes to copy from " +
                "the user's LDAP entry into the AuthToken. e.g use " +
                "'mail' to copy user's email address for subjectAltName");
        mExtendedPluginInfo.add(PROP_LDAPBYTEATTRS + ";string;" +
                "Comma-separated list of binary LDAP attributes to copy" +
                " from the user's LDAP entry into the AuthToken");
        mExtendedPluginInfo.add("ldap.ldapconn.host;string,required;" +
                "LDAP host to connect to");
        mExtendedPluginInfo.add("ldap.ldapconn.port;number,required;" +
                "LDAP port number (use 389, or 636 if SSL)");
        mExtendedPluginInfo.add("ldap.ldapconn.secureConn;boolean;" +
                "Use SSL to connect to directory?");
        mExtendedPluginInfo.add("ldap.ldapconn.version;choice(3,2);" +
                "LDAP protocol version");
        mExtendedPluginInfo.add("ldap.basedn;string,required;Base DN to start searching " +
                "under. If your user's DN is 'uid=jsmith, o=company', you " +
                "might want to use 'o=company' here");
        mExtendedPluginInfo.add("ldap.minConns;number;number of connections " +
                "to keep open to directory server. Default 5.");
        mExtendedPluginInfo.add("ldap.maxConns;number;when needed, connection " +
                "pool can grow to this many (multiplexed) connections. Default 1000.");
    }

    /**
     * Default constructor, initialization must follow.
     */
    public DirBasedAuthentication() {
    }

    /**
     * Initializes the UidPwdDirBasedAuthentication auth manager.
     *
     * Takes the following configuration parameters: <br>
     *
     * <pre>
     * 	ldap.basedn             - the ldap base dn.
     * 	ldap.ldapconn.host      - the ldap host.
     * 	ldap.ldapconn.port      - the ldap port
     * 	ldap.ldapconn.secureConn - whether port should be secure
     * 	ldap.minConns           - minimum connections
     * 	ldap.maxConns           - max connections
     * 	dnpattern               - dn pattern.
     * </pre>
     * <p>
     * <i><b>dnpattern</b></i> is a string representing a subject name pattern to formulate from the directory
     * attributes and entry dn. If empty or not set, the ldap entry DN will be used as the certificate subject name.
     * <p>
     * The syntax is
     *
     * <pre>
     *     dnpattern = SubjectNameComp *[ "," SubjectNameComp ]
     *
     *     SubjectNameComponent = DnComp | EntryComp | ConstantComp
     *     DnComp = CertAttr "=" "$dn" "." DnAttr "." Num
     *     EntryComp = CertAttr "=" "$attr" "." EntryAttr "." Num
     *     ConstantComp = CertAttr "=" Constant
     *     DnAttr    =  an attribute in the Ldap entry dn
     *     EntryAttr =  an attribute in the Ldap entry
     *     CertAttr  =  a Component in the Certificate Subject Name
     *                  (multiple AVA in one RDN not supported)
     *     Num       =  the nth value of tha attribute  in the dn or entry.
     *     Constant  =  Constant String, with any accepted ldap string value.
     *
     * </pre>
     * <p>
     * <b>Example:</b>
     *
     * <pre>
     * dnpattern:
     *     E=$attr.mail.1, CN=$attr.cn, OU=$attr.ou.2, O=$dn.o, C=US
     * <br>
     * Ldap entry dn:
     *     UID=joesmith, OU=people, O=Acme.com
     * <br>
     * Ldap attributes:
     *     cn: Joe Smith
     *     sn: Smith
     *     mail: joesmith@acme.com
     *     mail: joesmith@redhat.com
     *     ou: people
     *     ou: IS
     *     <i>etc.</i>
     * </pre>
     * <p>
     * The subject name formulated in the cert will be : <br>
     *
     * <pre>
     *   E=joesmith@acme.com, CN=Joe Smith, OU=Human Resources, O=Acme.com, C=US
     *
     *      E = the first 'mail' ldap attribute value in user's entry - joesmithe@acme.com
     *      CN = the (first) 'cn' ldap attribute value in the user's entry - Joe Smith
     *      OU = the second 'ou' value in the ldap entry - IS
     *      O = the (first) 'o' value in the user's entry DN - "Acme.com"
     *      C = the constant string "US"
     * </pre>
     *
     * @param name The name for this authentication manager instance.
     * @param implName The name of the authentication manager plugin.
     * @param config - The configuration store for this instance.
     * @exception EBaseException If an error occurs during initialization.
     */
    public void init(String name, String implName, IConfigStore config)
            throws EBaseException {
        init(name, implName, config, true);
    }

    public void init(String name, String implName, IConfigStore config, boolean needBaseDN)
            throws EBaseException {
        mName = name;
        mImplName = implName;
        mConfig = config;

        /* initialize ldap server configuration */
        mLdapConfig = mConfig.getSubStore(PROP_LDAP);
        if (needBaseDN)
            mBaseDN = mLdapConfig.getString(PROP_BASEDN);
        if (needBaseDN && ((mBaseDN == null) || (mBaseDN.length() == 0) || (mBaseDN.trim().equals(""))))
            throw new EPropertyNotFound(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED", "basedn"));
        mConnFactory = CMS.getLdapAnonConnFactory();
        mConnFactory.init(mLdapConfig);

        /* initialize dn pattern */
        String pattern = mConfig.getString(PROP_DNPATTERN, null);

        if (pattern == null || pattern.length() == 0)
            pattern = DEFAULT_DNPATTERN;
        mPattern = new DNPattern(pattern);
        String[] patternLdapAttrs = mPattern.getLdapAttrs();

        /* initialize ldap string attribute list */
        String ldapStringAttrs = mConfig.getString(PROP_LDAPSTRINGATTRS, null);

        if (ldapStringAttrs == null) {
            mLdapStringAttrs = patternLdapAttrs;
        } else {
            StringTokenizer pAttrs =
                    new StringTokenizer(ldapStringAttrs, ",", false);
            int begin = 0;

            if (patternLdapAttrs != null && patternLdapAttrs.length > 0) {
                mLdapStringAttrs = new String[
                        patternLdapAttrs.length + pAttrs.countTokens()];
                System.arraycopy(patternLdapAttrs, 0,
                        mLdapStringAttrs, 0, patternLdapAttrs.length);
                begin = patternLdapAttrs.length;
            } else {
                mLdapStringAttrs = new String[pAttrs.countTokens()];
            }
            for (int i = begin; i < mLdapStringAttrs.length; i++) {
                mLdapStringAttrs[i] = ((String) pAttrs.nextElement()).trim();
            }
        }

        /* initialize ldap byte[] attribute list */
        String ldapByteAttrs = mConfig.getString(PROP_LDAPBYTEATTRS, null);

        if (ldapByteAttrs == null) {
            mLdapByteAttrs = new String[0];
        } else {
            StringTokenizer byteAttrs =
                    new StringTokenizer(ldapByteAttrs, ",", false);

            mLdapByteAttrs = new String[byteAttrs.countTokens()];
            for (int j = 0; j < mLdapByteAttrs.length; j++) {
                mLdapByteAttrs[j] = ((String) byteAttrs.nextElement()).trim();
            }
        }

        /* make the combined list */
        mLdapAttrs =
                new String[mLdapStringAttrs.length + mLdapByteAttrs.length];
        System.arraycopy(mLdapStringAttrs, 0, mLdapAttrs,
                0, mLdapStringAttrs.length);
        System.arraycopy(mLdapByteAttrs, 0, mLdapAttrs,
                mLdapStringAttrs.length, mLdapByteAttrs.length);

        log(ILogger.LL_INFO, CMS.getLogMessage("CMS_AUTH_INIT_DONE"));
    }

    /**
     * gets the name of this authentication manager instance
     */
    public String getName() {
        return mName;
    }

    /**
     * gets the plugin name of this authentication manager.
     */
    public String getImplName() {
        return mImplName;
    }

    /**
     * Authenticates user through LDAP by a set of credentials.
     * Resulting AuthToken a TOKEN_CERTINFO field of a X509CertInfo
     * <p>
     *
     * @param authCred Authentication credentials, CRED_UID and CRED_PWD.
     * @return A AuthToken with a TOKEN_SUBJECT of X500name type.
     * @exception com.netscape.certsrv.authentication.EMissingCredential
     *                If a required authentication credential is missing.
     * @exception com.netscape.certsrv.authentication.EInvalidCredentials
     *                If credentials failed authentication.
     * @exception com.netscape.certsrv.base.EBaseException
     *                If an internal error occurred.
     * @see com.netscape.certsrv.authentication.AuthToken
     */
    public IAuthToken authenticate(IAuthCredentials authCred)
            throws EMissingCredential, EInvalidCredentials, EBaseException {
        String userdn = null;
        LDAPConnection conn = null;
        AuthToken authToken = new AuthToken(this);

        try {
            if (mConnFactory == null) {
                conn = null;
            } else {
                conn = mConnFactory.getConn();
            }

            // authenticate the user and get a user entry.
            userdn = authenticate(conn, authCred, authToken);
            authToken.set(USER_DN, userdn);

            // formulate the cert info.
            // set each seperatly since otherwise they won't serialize
            // in the request queue.
            X509CertInfo certInfo = new X509CertInfo();

            formCertInfo(conn, userdn, certInfo, authToken);

            // set subject name.
            try {
                CertificateSubjectName subjectname = (CertificateSubjectName)
                        certInfo.get(X509CertInfo.SUBJECT);

                if (subjectname != null)
                    authToken.set(AuthToken.TOKEN_CERT_SUBJECT,
                            subjectname.toString());
            } // error means it's not set.
            catch (CertificateException e) {
            } catch (IOException e) {
            }

            // set validity if any
            try {
                CertificateValidity validity = (CertificateValidity)
                        certInfo.get(X509CertInfo.VALIDITY);

                if (validity != null) {
                    // the gets throws IOException but only if attribute
                    // not recognized. In these cases they are always.
                    authToken.set(AuthToken.TOKEN_CERT_NOTBEFORE,
                            (Date) validity.get(CertificateValidity.NOT_BEFORE));
                    authToken.set(AuthToken.TOKEN_CERT_NOTAFTER,
                            (Date) validity.get(CertificateValidity.NOT_AFTER));
                }
            } // error means it's not set.
            catch (CertificateException e) {
            } catch (IOException e) {
            }

            // set extensions if any.
            try {
                CertificateExtensions extensions = (CertificateExtensions)
                        certInfo.get(X509CertInfo.EXTENSIONS);

                if (extensions != null)
                    authToken.set(AuthToken.TOKEN_CERT_EXTENSIONS, extensions);
            } // error means it's not set.
            catch (CertificateException e) {
            } catch (IOException e) {
            }

        } finally {
            if (conn != null)
                mConnFactory.returnConn(conn);
        }

        return authToken;
    }

    /**
     * get the list of required credentials.
     *
     * @return list of required credentials as strings.
     */
    public abstract String[] getRequiredCreds();

    /**
     * Returns a list of configuration parameter names.
     * The list is passed to the configuration console so instances of
     * this implementation can be configured through the console.
     *
     * @return String array of configuration parameter names.
     */
    public abstract String[] getConfigParams();

    /**
     * disconnects the ldap connections
     */
    public void shutdown() {
        try {
            if (mConnFactory != null) {
                mConnFactory.reset();
            }
        } catch (ELdapException e) {
            // ignore
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMS_AUTH_SHUTDOWN_ERROR", e.toString()));
        }
    }

    /**
     * Gets the configuration substore used by this authentication manager
     *
     * @return configuration store
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * Authenticates a user through directory based a set of credentials.
     *
     * @param authCreds The authentication credentials.
     * @return The user's ldap entry dn.
     * @exception EInvalidCredentials If the uid and password are not valid
     * @exception EBaseException If an internal error occurs.
     */
    protected abstract String authenticate(
            LDAPConnection conn, IAuthCredentials authCreds, AuthToken token)
            throws EBaseException;

    /**
     * Formulate the cert info.
     *
     * @param conn A LDAP Connection authenticated to user to use.
     * @param userdn The user's dn.
     * @param certinfo A certinfo object to fill.
     * @param token A authentication token to fill.
     * @exception EBaseException If an internal error occurs.
     */
    protected void formCertInfo(LDAPConnection conn,
            String userdn,
            X509CertInfo certinfo,
            AuthToken token)
            throws EBaseException {
        String dn = null;
        // get ldap attributes to retrieve.
        String[] attrs = getLdapAttrs();

        // retrieve the attributes.
        try {
            if (conn != null) {
                LDAPEntry entry = null;
                LDAPSearchResults results =
                        conn.search(userdn, LDAPv2.SCOPE_BASE, "objectclass=*",
                                attrs, false);

                if (!results.hasMoreElements()) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("CMS_AUTH_NO_ATTR_ERROR"));
                    throw new EAuthException(CMS.getUserMessage("CMS_AUTHENTICATION_LDAPATTRIBUTES_NOT_FOUND"));
                }
                entry = results.next();

                // formulate the subject dn
                try {
                    dn = formSubjectName(entry);
                } catch (EBaseException e) {
                    //e.printStackTrace();
                    throw e;
                }
                // Put selected values from the entry into the token
                setAuthTokenValues(entry, token);
            } else {
                dn = userdn;
            }

            // add anything else in cert info such as validity, extensions
            // (nothing now)

            // pack the dn into X500name and set subject name.
            if (dn.length() == 0) {
                EBaseException ex =
                        new EAuthException(CMS.getUserMessage("CMS_AUTHENTICATION_EMPTY_DN_FORMED", mName));

                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMS_AUTH_NO_DN_ERROR", ex.toString()));
                throw ex;
            }
            X500Name subjectdn = new X500Name(dn);

            certinfo.set(X509CertInfo.SUBJECT,
                    new CertificateSubjectName(subjectdn));
        } catch (LDAPException e) {
            switch (e.getLDAPResultCode()) {
            case LDAPException.SERVER_DOWN:
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMS_AUTH_NO_AUTH_ATTR_ERROR"));
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), "" + conn.getPort()));

            case LDAPException.NO_SUCH_OBJECT:
            case LDAPException.LDAP_PARTIAL_RESULTS:
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMS_AUTH_NO_USER_ENTRY_ERROR", userdn));

                // fall to below.
            default:
                log(ILogger.LL_FAILURE, CMS.getLogMessage("LDAP_ERROR", e.toString()));
                throw new ELdapException(
                        CMS.getUserMessage("CMS_LDAP_OTHER_LDAP_EXCEPTION",
                                e.errorCodeToString()));
            }
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMS_AUTH_CREATE_SUBJECT_ERROR", userdn, e.getMessage()));
            throw new EFormSubjectDN(CMS.getUserMessage("CMS_AUTHENTICATION_FORM_SUBJECTDN_ERROR"));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMS_AUTH_CREATE_CERTINFO_ERROR", userdn, e.getMessage()));
            throw new EFormSubjectDN(CMS.getUserMessage("CMS_AUTHENTICATION_FORM_SUBJECTDN_ERROR"));
        }
    }

    /**
     * Copy values from the LDAPEntry into the AuthToken. The
     * list of values that should be store this way is given in
     * a the ldapAttributes configuration parameter.
     */
    protected void setAuthTokenValues(LDAPEntry e, AuthToken tok) {
        for (int i = 0; i < mLdapStringAttrs.length; i++)
            setAuthTokenStringValue(mLdapStringAttrs[i], e, tok);
        for (int j = 0; j < mLdapByteAttrs.length; j++)
            setAuthTokenByteValue(mLdapByteAttrs[j], e, tok);
    }

    protected void setAuthTokenStringValue(
            String name, LDAPEntry entry, AuthToken tok) {
        LDAPAttribute values = entry.getAttribute(name);

        if (values == null)
            return;

        Vector<String> v = new Vector<String>();
        @SuppressWarnings("unchecked")
        Enumeration<String> e = values.getStringValues();

        while (e.hasMoreElements()) {
            v.addElement(e.nextElement());
        }

        String a[] = new String[v.size()];

        v.copyInto(a);

        tok.set(name, a);
    }

    protected void setAuthTokenByteValue(
            String name, LDAPEntry entry, AuthToken tok) {
        LDAPAttribute values = entry.getAttribute(name);

        if (values == null)
            return;

        Vector<byte[]> v = new Vector<byte[]>();
        @SuppressWarnings("unchecked")
        Enumeration<byte[]> e = values.getByteValues();

        while (e.hasMoreElements()) {
            v.addElement(e.nextElement());
        }

        byte[][] a = new byte[v.size()][];

        v.copyInto(a);

        tok.set(name, a);
    }

    /**
     * Return a list of LDAP attributes with String values to retrieve.
     * Subclasses can override to return any set of attributes.
     *
     * @return Array of LDAP attributes to retrieve from the directory.
     */
    protected String[] getLdapAttrs() {
        return mLdapAttrs;
    }

    /**
     * Return a list of LDAP attributes with byte[] values to retrieve.
     * Subclasses can override to return any set of attributes.
     *
     * @return Array of LDAP attributes to retrieve from the directory.
     */
    protected String[] getLdapByteAttrs() {
        return mLdapByteAttrs;
    }

    /**
     * Formulate the subject name
     *
     * @param entry The LDAP entry
     * @return The subject name string.
     * @exception EBaseException If an internal error occurs.
     */
    protected String formSubjectName(LDAPEntry entry)
            throws EAuthException {
        if (mPattern.mPatternString == null)
            return entry.getDN();

        /*
         if (mTestDNString != null) {
         mPattern.mTestDN = mTestDNString;
         //System.out.println("Set DNPattern.mTestDN to "+mPattern.mTestDN);
        }
        */

        String dn = mPattern.formDN(entry);

        CMS.debug("DirBasedAuthentication: formed DN '" + dn + "'");
        return dn;
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
        mLogger.log(ILogger.EV_SYSTEM, null, ILogger.S_AUTHENTICATION,
                level, msg);
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] s = Utils.getStringArrayFromVector(mExtendedPluginInfo);

        return s;

    }

}
