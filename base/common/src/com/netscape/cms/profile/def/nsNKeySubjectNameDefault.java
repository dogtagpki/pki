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
package com.netscape.cms.profile.def;

//ldap java sdk
import java.io.IOException;
import java.util.Locale;
import java.util.StringTokenizer;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;
import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.ldap.ILdapConnFactory;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;

/**
 * This class implements an enrollment default policy
 * that populates server-side configurable subject name
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class nsNKeySubjectNameDefault extends EnrollDefault {

    public static final String PROP_LDAP = "ldap";
    public static final String PROP_PARAMS = "params";
    public static final String CONFIG_DNPATTERN = "dnpattern";
    public static final String CONFIG_LDAP_STRING_ATTRS = "ldapStringAttributes";
    public static final String CONFIG_LDAP_HOST = "ldap.ldapconn.host";
    public static final String CONFIG_LDAP_PORT = "ldap.ldapconn.port";
    public static final String CONFIG_LDAP_SEC_CONN = "ldap.ldapconn.secureConn";
    public static final String CONFIG_LDAP_VER = "ldap.ldapconn.Version";
    public static final String CONFIG_LDAP_BASEDN = "ldap.basedn";
    public static final String CONFIG_LDAP_MIN_CONN = "ldap.minConns";
    public static final String CONFIG_LDAP_MAX_CONN = "ldap.maxConns";

    public static final String VAL_NAME = "name";

    public static final String CONFIG_LDAP_VERS =
            "2,3";

    /* default dn pattern if left blank or not set in the config */
    protected static String DEFAULT_DNPATTERN =
            "CN=$request.aoluid$, E=$request.mail$";

    /* ldap configuration sub-store */
    boolean mInitialized = false;
    protected IConfigStore mInstConfig;
    protected IConfigStore mLdapConfig;
    protected IConfigStore mParamsConfig;

    /* ldap base dn */
    protected String mBaseDN = null;

    /* factory of anonymous ldap connections */
    protected ILdapConnFactory mConnFactory = null;

    /* the list of LDAP attributes with string values to retrieve to
     * form the subject dn. */
    protected String[] mLdapStringAttrs = null;

    public nsNKeySubjectNameDefault() {
        super();
        addConfigName(CONFIG_DNPATTERN);
        addConfigName(CONFIG_LDAP_STRING_ATTRS);
        addConfigName(CONFIG_LDAP_HOST);
        addConfigName(CONFIG_LDAP_PORT);
        addConfigName(CONFIG_LDAP_SEC_CONN);
        addConfigName(CONFIG_LDAP_VER);
        addConfigName(CONFIG_LDAP_BASEDN);
        addConfigName(CONFIG_LDAP_MIN_CONN);
        addConfigName(CONFIG_LDAP_MAX_CONN);

        addValueName(CONFIG_DNPATTERN);
        addValueName(CONFIG_LDAP_STRING_ATTRS);
        addValueName(CONFIG_LDAP_HOST);
        addValueName(CONFIG_LDAP_PORT);
        addValueName(CONFIG_LDAP_SEC_CONN);
        addValueName(CONFIG_LDAP_VER);
        addValueName(CONFIG_LDAP_BASEDN);
        addValueName(CONFIG_LDAP_MIN_CONN);
        addValueName(CONFIG_LDAP_MAX_CONN);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        mInstConfig = config;
        super.init(profile, config);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        CMS.debug("nsNKeySubjectNameDefault: in getConfigDescriptor, name=" + name);
        if (name.equals(CONFIG_DNPATTERN)) {
            return new Descriptor(IDescriptor.STRING,
                    null, null, CMS.getUserMessage(locale,
                            "CMS_PROFILE_SUBJECT_NAME"));
        } else if (name.equals(CONFIG_LDAP_STRING_ATTRS)) {
            return new Descriptor(IDescriptor.STRING,
                                  null,
                                  null,
                                  CMS.getUserMessage(locale, "CMS_PROFILE_NSNKEY_LDAP_STRING_ATTRS"));
        } else if (name.equals(CONFIG_LDAP_HOST)) {
            return new Descriptor(IDescriptor.STRING,
                                  null,
                                  null,
                                  CMS.getUserMessage(locale, "CMS_PROFILE_NSNKEY_HOST_NAME"));
        } else if (name.equals(CONFIG_LDAP_PORT)) {
            return new Descriptor(IDescriptor.STRING,
                                  null,
                                  null,
                                  CMS.getUserMessage(locale, "CMS_PROFILE_NSNKEY_PORT_NUMBER"));
        } else if (name.equals(CONFIG_LDAP_SEC_CONN)) {
            return new Descriptor(IDescriptor.BOOLEAN,
                                  null,
                                  "false",
                                  CMS.getUserMessage(locale, "CMS_PROFILE_NSNKEY_SECURE_CONN"));
        } else if (name.equals(CONFIG_LDAP_VER)) {
            return new Descriptor(IDescriptor.CHOICE, CONFIG_LDAP_VERS,
                    "3",
                    CMS.getUserMessage(locale, "CMS_PROFILE_NSNKEY_LDAP_VERSION"));
        } else if (name.equals(CONFIG_LDAP_BASEDN)) {
            return new Descriptor(IDescriptor.STRING,
                                  null,
                                  null,
                                  CMS.getUserMessage(locale, "CMS_PROFILE_NSNKEY_BASEDN"));
        } else if (name.equals(CONFIG_LDAP_MIN_CONN)) {
            return new Descriptor(IDescriptor.STRING,
                                  null,
                                  null,
                                  CMS.getUserMessage(locale, "CMS_PROFILE_NSNKEY_LDAP_MIN_CONN"));
        } else if (name.equals(CONFIG_LDAP_MAX_CONN)) {
            return new Descriptor(IDescriptor.STRING,
                                  null,
                                  null,
                                  CMS.getUserMessage(locale, "CMS_PROFILE_NSNKEY_LDAP_MAX_CONN"));
        } else {
            return null;
        }
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        CMS.debug("nsNKeySubjectNameDefault: in getValueDescriptor name=" + name);

        if (name.equals(VAL_NAME)) {
            return new Descriptor(IDescriptor.STRING,
                    null,
                    null,
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_SUBJECT_NAME"));
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {

        CMS.debug("nsNKeySubjectNameDefault: in setValue, value=" + value);

        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
        if (name.equals(VAL_NAME)) {
            X500Name x500name = null;

            try {
                x500name = new X500Name(value);
            } catch (IOException e) {
                CMS.debug("nsNKeySubjectNameDefault: setValue " + e.toString());
                // failed to build x500 name
            }
            CMS.debug("nsNKeySubjectNameDefault: setValue name=" + x500name);
            try {
                info.set(X509CertInfo.SUBJECT,
                        new CertificateSubjectName(x500name));
            } catch (Exception e) {
                // failed to insert subject name
                CMS.debug("nsNKeySubjectNameDefault: setValue " + e.toString());
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        CMS.debug("nsNKeySubjectNameDefault: in getValue, name=" + name);
        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
        if (name.equals(VAL_NAME)) {
            CertificateSubjectName sn = null;

            try {
                CMS.debug("nsNKeySubjectNameDefault: getValue info=" + info);
                sn = (CertificateSubjectName)
                        info.get(X509CertInfo.SUBJECT);
                CMS.debug("nsNKeySubjectNameDefault: getValue name=" + sn);
                return sn.toString();
            } catch (Exception e) {
                // nothing
                CMS.debug("nsNKeySubjectNameDefault: getValue " + e.toString());

            }
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getText(Locale locale) {
        CMS.debug("nsNKeySubjectNameDefault: in getText");
        return CMS.getUserMessage(locale, "CMS_PROFILE_SUBJECT_NAME",
                getConfig(CONFIG_DNPATTERN));
    }

    public void ldapInit()
            throws EProfileException {
        if (mInitialized == true)
            return;

        CMS.debug("nsNKeySubjectNameDefault: ldapInit(): begin");

        try {
            // cfu - XXX do more error handling here later
            /* initialize ldap server configuration */
            mParamsConfig = mInstConfig.getSubStore(PROP_PARAMS);
            mLdapConfig = mParamsConfig.getSubStore(PROP_LDAP);
            mBaseDN = mParamsConfig.getString(CONFIG_LDAP_BASEDN, null);
            mConnFactory = CMS.getLdapAnonConnFactory();
            mConnFactory.init(mLdapConfig);

            /* initialize dn pattern */
            String pattern = mParamsConfig.getString(CONFIG_DNPATTERN, null);

            if (pattern == null || pattern.length() == 0)
                pattern = DEFAULT_DNPATTERN;

            /* initialize ldap string attribute list */
            String ldapStringAttrs = mParamsConfig.getString(CONFIG_LDAP_STRING_ATTRS, null);

            if ((ldapStringAttrs != null) && (ldapStringAttrs.length() != 0)) {
                StringTokenizer pAttrs =
                        new StringTokenizer(ldapStringAttrs, ",", false);

                mLdapStringAttrs = new String[pAttrs.countTokens()];

                for (int i = 0; i < mLdapStringAttrs.length; i++) {
                    mLdapStringAttrs[i] = ((String) pAttrs.nextElement()).trim();
                }
            }
            CMS.debug("nsNKeySubjectNameDefault: ldapInit(): done");
            mInitialized = true;
        } catch (Exception e) {
            CMS.debug("nsNKeySubjectNameDefault: ldapInit(): " + e.toString());
            // throw EProfileException...
            throw new EProfileException("ldap init failure: " + e.toString());
        }
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        X500Name name = null;
        CMS.debug("nsNKeySubjectNameDefault: in populate");
        ldapInit();
        try {
            // cfu - this goes to ldap
            String subjectName = getSubjectName(request);
            CMS.debug("subjectName=" + subjectName);
            if (subjectName == null || subjectName.equals(""))
                return;

            name = new X500Name(subjectName);
        } catch (IOException e) {
            // failed to build x500 name
            CMS.debug("nsNKeySubjectNameDefault: populate " + e.toString());
        }
        if (name == null) {
            // failed to build x500 name
        }
        try {
            info.set(X509CertInfo.SUBJECT,
                    new CertificateSubjectName(name));
        } catch (Exception e) {
            // failed to insert subject name
            CMS.debug("nsNKeySubjectNameDefault: populate " + e.toString());
        }
    }

    private String getSubjectName(IRequest request)
            throws EProfileException, IOException {

        CMS.debug("nsNKeySubjectNameDefault: in getSubjectName");

        String pattern = getConfig(CONFIG_DNPATTERN);
        if (pattern == null || pattern.equals("")) {
            pattern = " ";
        }

        LDAPConnection conn = null;
        String userdn = null;
        String sbjname = "";
        // get DN from ldap to fill request
        try {
            if (mConnFactory == null) {
                conn = null;
                CMS.debug("nsNKeySubjectNameDefault: getSubjectName(): no LDAP connection");
                throw new EProfileException("no LDAP connection");
            } else {
                conn = mConnFactory.getConn();
                if (conn == null) {
                    CMS.debug("nsNKeySubjectNameDefault::getSubjectName() - " +
                               "no LDAP connection");
                    throw new EProfileException("no LDAP connection");
                }
                CMS.debug("nsNKeySubjectNameDefault: getSubjectName(): got LDAP connection");
            }

            if (request != null) {
                CMS.debug("pattern = " + pattern);
                sbjname = mapPattern(request, pattern);
                CMS.debug("nsNKeySubjectNameDefault: getSubjectName(): subject name mapping done");
            } else {
                CMS.debug("nsNKeySubjectNameDefault::getSubjectName() - " +
                           "request is null!");
                throw new EProfileException("request is null");
            }
            // retrieve the attributes
            // get user dn.
            CMS.debug("nsNKeySubjectNameDefault: getSubjectName(): about to search with basedn = " + mBaseDN);
            LDAPSearchResults res = conn.search(mBaseDN,
                    LDAPv2.SCOPE_SUB, "(aoluid=" + request.getExtDataInString("aoluid") + ")", null, false);

            if (res.hasMoreElements()) {
                LDAPEntry entry = res.next();

                userdn = entry.getDN();
            } else {// put into property file later - cfu
                CMS.debug("nsNKeySubjectNameDefault: getSubjectName(): screen name does not exist");
                throw new EProfileException("screenname does not exist");
            }
            CMS.debug("nsNKeySubjectNameDefault: getSubjectName(): retrieved entry for aoluid = "
                    + request.getExtDataInString("aoluid"));
            ;

            LDAPEntry entry = null;
            CMS.debug("nsNKeySubjectNameDefault: getSubjectName(): about to search with "
                    + mLdapStringAttrs.length + " attributes");
            LDAPSearchResults results =
                    conn.search(userdn, LDAPv2.SCOPE_BASE, "objectclass=*",
                            mLdapStringAttrs, false);

            if (!results.hasMoreElements()) {
                CMS.debug("nsNKeySubjectNameDefault: getSubjectName(): no attributes");
                throw new EProfileException("no ldap attributes found");
            }
            entry = results.next();
            // set attrs into request
            for (int i = 0; i < mLdapStringAttrs.length; i++) {
                LDAPAttribute la =
                        entry.getAttribute(mLdapStringAttrs[i]);
                if (la != null) {
                    String[] sla = la.getStringValueArray();
                    CMS.debug("nsNKeySubjectNameDefault: getSubjectName(): got attribute: " + sla[0]);
                    request.setExtData(mLdapStringAttrs[i], sla[0]);
                }
            }
            CMS.debug("nsNKeySubjectNameDefault: getSubjectName(): attributes set in request");
        } catch (Exception e) {
            CMS.debug("nsNKeySubjectNameDefault: getSubjectName(): " + e.toString());
            throw new EProfileException("getSubjectName() failure: " + e.toString());
        } finally {
            try {
                if (conn != null)
                    mConnFactory.returnConn(conn);
            } catch (Exception e) {
                throw new EProfileException("nsNKeySubjectNameDefault: getSubjectName(): connection return failure");
            }
        }
        return sbjname;

    }
}
