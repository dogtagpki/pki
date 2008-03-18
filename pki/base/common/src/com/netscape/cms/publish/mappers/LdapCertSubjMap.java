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


import java.io.*;
import java.util.*;
import java.security.*;
import java.security.cert.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.apps.*;
import netscape.security.x509.*;
import netscape.ldap.*;
import com.netscape.certsrv.ldap.*;
import com.netscape.certsrv.publish.*;


/** 
 * Maps a X509 certificate to a LDAP entry by finding an LDAP entry
 * which has an attribute whose contents are equal to the cert subject name.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class LdapCertSubjMap implements ILdapMapper, IExtendedPluginInfo {
    public static final String LDAP_CERTSUBJNAME_ATTR = "certSubjectName";
    protected String mSearchBase = null;
    protected String mCertSubjNameAttr = LDAP_CERTSUBJNAME_ATTR;

    private ILogger mLogger = CMS.getLogger();
    protected IConfigStore mConfig = null;
    boolean mInited = false;

    public LdapCertSubjMap() {
        // need to setup the mSearchBase via configuration
    }

    /**
     * constructs a certificate subject name mapper with search base.
     * @param searchBase the dn to start searching for the certificate 
     * subject name.
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

    public String getImplName() {
        return "LdapCertSubjMap";
    }

    public String getDescription() {
        return "LdapCertSubjMap";
    }

    public Vector getDefaultParams() {
        Vector v = new Vector();

        v.addElement("certSubjNameAttr=" + mCertSubjNameAttr);
        v.addElement("searchBase=");
        return v;
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                "certSubjNameAttr;string;Name of Ldap attribute containing cert subject name",
                "searchBase;string;Base DN to search from",
                IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-ldappublish-mapper-certsubjmapper",
                IExtendedPluginInfo.HELP_TEXT +
                ";This plugin assumes you want to publish to an LDAP entry which has " +
                "an attribute whose contents are equal to the cert subject name"
            };

        return params;
    }
	
    public Vector getInstanceParams() {
        Vector v = new Vector();

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
        return v;
    }

    public IConfigStore getConfigStore() {
        return mConfig;
    }

    public void init(IConfigStore config)
        throws EBaseException {
        if (mInited == true)
            return;
        mConfig = config;
        mCertSubjNameAttr = config.getString("certSubjNameAttr",
                    LDAP_CERTSUBJNAME_ATTR);
        mSearchBase = config.getString("searchBase");
        mInited = true;
    }

    /**
     * Finds the entry for the certificate by looking for the cert 
     * subject name in the subject name attribute.
     * 
     * @param conn - the LDAP connection.
     * @param obj - the X509Certificate.
     */ 
    public String
    map(LDAPConnection conn, Object obj)
        throws ELdapException {
        if (conn == null)
            return null;
        X500Name subjectDN = null;

        try {
            X509Certificate cert = (X509Certificate) obj;

            subjectDN = 
                    (X500Name) ((X509Certificate) cert).getSubjectDN();

            CMS.debug("LdapCertSubjMap: cert subject dn:" + subjectDN.toString());
        } catch (ClassCastException e) {
            try {
                X509CRLImpl crl = (X509CRLImpl) obj;

                subjectDN = 
                        (X500Name) ((X509CRLImpl) crl).getIssuerDN();

                CMS.debug("LdapCertSubjMap: crl issuer dn: " +
                    subjectDN.toString());
            }catch (ClassCastException ex) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_NOT_SUPPORTED_OBJECT"));
                return null;
            }
        }
        try {
            boolean hasCert = false;
            boolean hasSubjectName = false;
            String[] attrs = new String[] { LDAPv3.NO_ATTRS }; 

            log(ILogger.LL_INFO, "search " + mSearchBase +
                " (" + mCertSubjNameAttr + "=" + subjectDN + ") " + mCertSubjNameAttr);

            LDAPSearchResults results = 
                conn.search(mSearchBase, LDAPv2.SCOPE_SUB, 
                    "(" + mCertSubjNameAttr + "=" + subjectDN + ")", attrs, false);
							
            LDAPEntry entry = results.next();

            if (results.hasMoreElements()) {
                log(ILogger.LL_FAILURE, 
                    CMS.getLogMessage("PUBLISH_MORE_THAN_ONE_ENTRY", "", subjectDN.toString()));
            }
            if (entry != null) {
                log(ILogger.LL_INFO, "entry found");
                return entry.getDN();
            }
            return null;
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("PUBLISH_NO_LDAP_SERVER"));
                throw new ELdapServerDownException(CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), "" + conn.getPort()));
            } else {
                log(ILogger.LL_FAILURE, 
                    CMS.getLogMessage("PUBLISH_DN_MAP_EXCEPTION", "LDAPException", e.toString()));
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_MATCH_FOUND", e.toString()));
            }
        }

        /*
         catch (IOException e) {
         log(ILogger.LL_FAILURE, 
         CMS.getLogMessage("PUBLISH_CANT_GET_SUBJECT", e.toString()));
         throw new ELdapException(
         LdapResources.GET_CERT_SUBJECT_DN_FAILED, e);
         }
         catch (CertificateEncodingException e) {
         log(ILogger.LL_FAILURE, 
         CMS.getLogMessage("PUBLISH_CANT_DECODE_CERT", e.toString()));
         throw new ELdapException(
         LdapResources.GET_DER_ENCODED_CERT_FAILED, e);
         }
         */
    }

    public String map(LDAPConnection conn, IRequest req, Object obj)
        throws ELdapException {
        return map(conn, obj);
    }

    private void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_LDAP, level, 
            "LdapCertSubjMap: " + msg);
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

}

