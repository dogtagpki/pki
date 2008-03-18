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
 * Maps a X509 certificate to a LDAP entry by using the subject name
 * of the certificate as the LDAP entry DN.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class LdapCertExactMap implements ILdapMapper, IExtendedPluginInfo {
    private ILogger mLogger = CMS.getLogger();
    protected IConfigStore mConfig = null;
    boolean mInited = false;

    /**
     * constructs a certificate subject name mapper with search base.
     */
    public LdapCertExactMap() {
    }

    public IConfigStore getConfigStore() {
        return mConfig;
    }

    public void init(IConfigStore config)
        throws EBaseException {
        if (mInited == true)
            return;
        mConfig = config;
        mInited = true;
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] params = {
                IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-ldappublish-mapper-certexactmapper",
                IExtendedPluginInfo.HELP_TEXT +
                ";Literally uses the subject name of the certificate as the DN to publish to"
            };

        return params;
    }

    public String getImplName() {
        return "LdapCertExactMap";
    }

    public String getDescription() {
        return "LdapCertExactMap";
    }

    public Vector getDefaultParams() {
        Vector v = new Vector();

        return v;
    }
	
    public Vector getInstanceParams() {
        Vector v = new Vector();

        return v;
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

            CMS.debug("LdapCertExactMap: cert subject dn:" + subjectDN.toString());
        } catch (ClassCastException e) {
            try {
                X509CRLImpl crl = (X509CRLImpl) obj;

                subjectDN = 
                        (X500Name) ((X509CRLImpl) crl).getIssuerDN();

                CMS.debug("LdapCertExactMap: crl issuer dn: " +
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

            log(ILogger.LL_INFO, "Searching for " + subjectDN.toString());

            LDAPSearchResults results = 
                conn.search(subjectDN.toString(), LDAPv2.SCOPE_BASE, 
                    "(objectclass=*)", attrs, false);
							
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
                log(ILogger.LL_FAILURE, CMS.getLogMessage("PUBLISH_DN_MAP_EXCEPTION", e.toString()));
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
            "LdapCertExactMap: " + msg);
    }

}

