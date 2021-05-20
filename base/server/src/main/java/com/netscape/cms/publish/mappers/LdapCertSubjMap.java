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
package com.netscape.cms.publish.mappers;

import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.Vector;

import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ELdapServerDownException;
import com.netscape.certsrv.publish.ILdapMapper;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmscore.apps.CMS;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;
import netscape.ldap.LDAPv3;

/**
 * Maps a X509 certificate to a LDAP entry by finding an LDAP entry
 * which has an attribute whose contents are equal to the cert subject name.
 *
 * @version $Revision$, $Date$
 */
public class LdapCertSubjMap implements ILdapMapper, IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LdapCertSubjMap.class);

    public static final String LDAP_CERTSUBJNAME_ATTR = "certSubjectName";
    protected String mSearchBase = null;
    protected String mCertSubjNameAttr = LDAP_CERTSUBJNAME_ATTR;
    protected boolean mUseAllEntries = false;

    protected IConfigStore mConfig = null;
    boolean mInited = false;

    public LdapCertSubjMap() {
        // need to setup the mSearchBase via configuration
    }

    /**
     * constructs a certificate subject name mapper with search base.
     *
     * @param searchBase the dn to start searching for the certificate
     *            subject name.
     */
    public LdapCertSubjMap(String searchBase) {
        if (searchBase == null)
            throw new IllegalArgumentException(
                    "a null argument to constructor " + this.getClass().getName());
        mSearchBase = searchBase;
        mInited = true;
    }

    /**
     * Constructor using non-ES cert map attribute name.
     *
     * @param searchBase entry to start search.
     * @param certSubjNameAttr attribute for certificate subject names.
     * @param certAttr attribute to find certificate.
     */
    public LdapCertSubjMap(String searchBase,
            String certSubjNameAttr, String certAttr) {
        if (searchBase == null ||
                certSubjNameAttr == null || certAttr == null)
            throw new IllegalArgumentException(
                    "a null argument to constructor " + this.getClass().getName());
        mCertSubjNameAttr = certSubjNameAttr;
        mSearchBase = searchBase;
        mInited = true;
    }

    public LdapCertSubjMap(String searchBase,
            String certSubjNameAttr, String certAttr, boolean useAllEntries) {
        if (searchBase == null ||
                certSubjNameAttr == null || certAttr == null)
            throw new IllegalArgumentException(
                    "a null argument to constructor " + this.getClass().getName());
        mCertSubjNameAttr = certSubjNameAttr;
        mSearchBase = searchBase;
        mUseAllEntries = useAllEntries;
        mInited = true;
    }

    @Override
    public String getImplName() {
        return "LdapCertSubjMap";
    }

    @Override
    public String getDescription() {
        return "LdapCertSubjMap";
    }

    @Override
    public Vector<String> getDefaultParams() {
        Vector<String> v = new Vector<>();

        v.addElement("certSubjNameAttr=" + mCertSubjNameAttr);
        v.addElement("searchBase=");
        v.addElement("useAllEntries=" + mUseAllEntries);
        return v;
    }

    @Override
    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                "certSubjNameAttr;string;Name of Ldap attribute containing cert subject name",
                "searchBase;string;Base DN to search from",
                "useAllEntries;boolean;Use all entries for publishing",
                IExtendedPluginInfo.HELP_TOKEN +
                        ";configuration-ldappublish-mapper-certsubjmapper",
                IExtendedPluginInfo.HELP_TEXT +
                        ";This plugin assumes you want to publish to an LDAP entry which has " +
                        "an attribute whose contents are equal to the cert subject name"
            };

        return params;
    }

    @Override
    public Vector<String> getInstanceParams() {
        Vector<String> v = new Vector<>();

        if (mCertSubjNameAttr == null) {
            v.addElement("certSubjNameAttr=");
        } else {
            v.addElement("certSubjNameAttr=" + mCertSubjNameAttr);
        }
        if (mSearchBase == null) {
            v.addElement("searchBase=");
        } else {
            v.addElement("searchBase=" + mSearchBase);
        }
        v.addElement("useAllEntries=" + mUseAllEntries);
        return v;
    }

    @Override
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    @Override
    public void init(IConfigStore config)
            throws EBaseException {
        if (mInited == true)
            return;
        mConfig = config;
        mCertSubjNameAttr = config.getString("certSubjNameAttr",
                    LDAP_CERTSUBJNAME_ATTR);
        mSearchBase = config.getString("searchBase");
        mUseAllEntries = config.getBoolean("useAllEntries", false);
        mInited = true;
    }

    /**
     * Finds the entry for the certificate by looking for the cert
     * subject name in the subject name attribute.
     *
     * @param conn - the LDAP connection.
     * @param obj - the X509Certificate.
     */
    @Override
    public String
            map(LDAPConnection conn, Object obj)
                    throws ELdapException {
        if (conn == null)
            return null;
        X500Name subjectDN = null;

        try {
            X509Certificate cert = (X509Certificate) obj;
            subjectDN = (X500Name) cert.getSubjectDN();

            logger.debug("LdapCertSubjMap: cert subject dn:" + subjectDN);

        } catch (ClassCastException e) {
            logger.warn("LdapCertSubjMap: " + e.getMessage(), e);
            try {
                X509CRLImpl crl = (X509CRLImpl) obj;
                subjectDN = (X500Name) crl.getIssuerDN();

                logger.debug("LdapCertSubjMap: crl issuer dn: " + subjectDN);
            } catch (ClassCastException ex) {
                logger.warn(CMS.getLogMessage("PUBLISH_NOT_SUPPORTED_OBJECT"), ex);
                return null;
            }
        }
        try {
            String[] attrs = new String[] { LDAPv3.NO_ATTRS };

            logger.info("LdapCertSubjMap: search " + mSearchBase + " (" + mCertSubjNameAttr + "=" + subjectDN + ") " + mCertSubjNameAttr);

            LDAPSearchResults results =
                    conn.search(mSearchBase, LDAPv2.SCOPE_SUB,
                            "(" + mCertSubjNameAttr + "=" + subjectDN + ")", attrs, false);

            LDAPEntry entry = results.next();

            if (results.hasMoreElements()) {
                logger.warn(CMS.getLogMessage("PUBLISH_MORE_THAN_ONE_ENTRY", "", subjectDN.toString()));
            }
            if (entry != null) {
                logger.info("LdapCertSubjMap: entry found");
                return entry.getDN();
            }
            return null;
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                logger.error(CMS.getLogMessage("PUBLISH_NO_LDAP_SERVER"), e);
                throw new ELdapServerDownException(CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), ""
                        + conn.getPort()));
            } else {
                logger.error(CMS.getLogMessage("PUBLISH_DN_MAP_EXCEPTION", "LDAPException", e.toString()), e);
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_MATCH_FOUND", e.toString()));
            }
        }

        /*
         catch (IOException e) {
         logger.error(CMS.getLogMessage("PUBLISH_CANT_GET_SUBJECT", e.toString()), e);
         throw new ELdapException(
         LdapResources.GET_CERT_SUBJECT_DN_FAILED, e);
         }
         catch (CertificateEncodingException e) {
         logger.error(CMS.getLogMessage("PUBLISH_CANT_DECODE_CERT", e.toString()), e);
         throw new ELdapException(
         LdapResources.GET_DER_ENCODED_CERT_FAILED, e);
         }
         */
    }

    @Override
    public String map(LDAPConnection conn, IRequest req, Object obj)
            throws ELdapException {
        return map(conn, obj);
    }

    public Vector<String> mapAll(LDAPConnection conn, Object obj)
            throws ELdapException {
        Vector<String> v = new Vector<>();

        if (conn == null)
            return null;
        X500Name subjectDN = null;

        try {
            X509Certificate cert = (X509Certificate) obj;
            subjectDN = (X500Name) cert.getSubjectDN();
            logger.debug("LdapCertSubjMap: cert subject dn:" + subjectDN);
        } catch (ClassCastException e) {
            logger.warn(CMS.getLogMessage("PUBLISH_NOT_SUPPORTED_OBJECT"), e);
            return v;
        }
        try {
            String[] attrs = new String[] { LDAPv3.NO_ATTRS };

            logger.info("LdapCertSubjMap: search " + mSearchBase + " (" + mCertSubjNameAttr + "=" + subjectDN + ") " + mCertSubjNameAttr);

            LDAPSearchResults results =
                    conn.search(mSearchBase, LDAPv2.SCOPE_SUB,
                            "(" + mCertSubjNameAttr + "=" + subjectDN + ")", attrs, false);

            while (results.hasMoreElements()) {
                LDAPEntry entry = results.next();
                String dn = entry.getDN();
                v.addElement(dn);
                logger.debug("LdapCertSubjMap: dn=" + dn);
            }
            logger.debug("LdapCertSubjMap: Number of entries: " + v.size());
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                logger.error(CMS.getLogMessage("PUBLISH_NO_LDAP_SERVER"), e);
                throw new ELdapServerDownException(CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), ""
                        + conn.getPort()));
            } else {
                logger.error(CMS.getLogMessage("PUBLISH_DN_MAP_EXCEPTION", "LDAPException", e.toString()), e);
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_MATCH_FOUND", e.toString()));
            }
        }

        return v;
    }

    public Vector<String> mapAll(LDAPConnection conn, IRequest req, Object obj)
            throws ELdapException {
        return mapAll(conn, obj);
    }

    /**
     * return search base
     */
    public String getSearchBase() {
        return mSearchBase;
    }

    /**
     * return certificate subject attribute
     */
    public String getCertSubjNameAttr() {
        return mCertSubjNameAttr;
    }

    public boolean useAllEntries() {
        return mUseAllEntries;
    }

}
