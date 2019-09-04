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
 * Maps a X509 certificate to a LDAP entry by using the subject name
 * of the certificate as the LDAP entry DN.
 *
 * @version $Revision$, $Date$
 */
public class LdapCertExactMap implements ILdapMapper, IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LdapCertExactMap.class);
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

    public Vector<String> getDefaultParams() {
        Vector<String> v = new Vector<String>();

        return v;
    }

    public Vector<String> getInstanceParams() {
        Vector<String> v = new Vector<String>();

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
            subjectDN = (X500Name) cert.getSubjectDN();

            logger.debug("LdapCertExactMap: cert subject dn:" + subjectDN.toString());
        } catch (ClassCastException e) {
            try {
                X509CRLImpl crl = (X509CRLImpl) obj;
                subjectDN = (X500Name) crl.getIssuerDN();

                logger.warn("LdapCertExactMap: crl issuer dn: " + subjectDN + ": " + e.getMessage(), e);
            } catch (ClassCastException ex) {
                logger.warn(CMS.getLogMessage("PUBLISH_NOT_SUPPORTED_OBJECT"), e);
                return null;
            }
        }
        try {
            String[] attrs = new String[] { LDAPv3.NO_ATTRS };

            logger.info("Searching for " + subjectDN.toString());

            LDAPSearchResults results =
                    conn.search(subjectDN.toString(), LDAPv2.SCOPE_BASE,
                            "(objectclass=*)", attrs, false);

            LDAPEntry entry = results.next();

            if (results.hasMoreElements()) {
                logger.warn(CMS.getLogMessage("PUBLISH_MORE_THAN_ONE_ENTRY", "", subjectDN.toString()));
            }
            if (entry != null) {
                logger.info("entry found");
                return entry.getDN();
            }
            return null;
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                // need to intercept this because message from LDAP is
                // "DSA is unavailable" which confuses with DSA PKI.
                logger.error(CMS.getLogMessage("PUBLISH_NO_LDAP_SERVER"), e);
                throw new ELdapServerDownException(CMS.getUserMessage("CMS_LDAP_SERVER_UNAVAILABLE", conn.getHost(), "" + conn.getPort()), e);
            } else {
                logger.error(CMS.getLogMessage("PUBLISH_DN_MAP_EXCEPTION", e.toString()), e);
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_NO_MATCH_FOUND", e.toString()), e);
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

    public String map(LDAPConnection conn, IRequest req, Object obj)
            throws ELdapException {
        return map(conn, obj);
    }
}
