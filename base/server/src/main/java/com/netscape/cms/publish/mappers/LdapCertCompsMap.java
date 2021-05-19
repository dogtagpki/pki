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

import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Vector;

import org.mozilla.jss.netscape.security.util.ObjectIdentifier;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;

import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.publish.ILdapMapper;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cmscore.apps.CMS;

import netscape.ldap.LDAPConnection;

/**
 * Maps a X509 certificate to a LDAP entry using AVAs in the certificate's
 * subject name to form the ldap search dn and filter.
 * Takes a optional root search dn.
 * The DN comps are used to form a LDAP entry to begin a subtree search.
 * The filter comps are used to form a search filter for the subtree.
 * If none of the DN comps matched, baseDN is used for the subtree.
 * If the baseDN is null and none of the DN comps matched, it is an error.
 * If none of the DN comps and filter comps matched, it is an error.
 * If just the filter comps is null, a base search is performed.
 *
 * @version $Revision$, $Date$
 */
public class LdapCertCompsMap
        extends LdapDNCompsMap implements ILdapMapper {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LdapCertCompsMap.class);

    public LdapCertCompsMap() {
        // need to support baseDN, dnComps, and filterComps
        // via configuration
    }

    /**
     * Constructor.
     *
     * The DN comps are used to form a LDAP entry to begin a subtree search.
     * The filter comps are used to form a search filter for the subtree.
     * If none of the DN comps matched, baseDN is used for the subtree.
     * If the baseDN is null and none of the DN comps matched, it is an error.
     * If none of the DN comps and filter comps matched, it is an error.
     * If just the filter comps is null, a base search is performed.
     *
     * @param baseDN The base DN.
     * @param dnComps Components to form the LDAP base dn for search.
     * @param filterComps Components to form the LDAP search filter.
     */
    public LdapCertCompsMap(String baseDN, ObjectIdentifier[] dnComps,
            ObjectIdentifier[] filterComps) {
        init(baseDN, dnComps, filterComps);
    }

    @Override
    public String getImplName() {
        return "LdapCertCompsMap";
    }

    @Override
    public String getDescription() {
        return "LdapCertCompsMap";
    }

    @Override
    public Vector<String> getDefaultParams() {
        Vector<String> v = super.getDefaultParams();

        return v;
    }

    @Override
    public Vector<String> getInstanceParams() {
        Vector<String> v = super.getInstanceParams();

        return v;
    }

    /**
     * constructor using non-standard certificate attribute.
     */
    public LdapCertCompsMap(String certAttr, String baseDN,
            ObjectIdentifier[] dnComps,
            ObjectIdentifier[] filterComps) {
        super(certAttr, baseDN, dnComps, filterComps);
    }

    @Override
    protected void init(String baseDN, ObjectIdentifier[] dnComps,
            ObjectIdentifier[] filterComps) {
        super.init(baseDN, dnComps, filterComps);
    }

    /**
     * Maps a certificate to LDAP entry.
     * Uses DN components and filter components to form a DN and
     * filter for a LDAP search.
     * If the formed DN is null the baseDN will be used.
     * If the formed DN is null and baseDN is null an error is thrown.
     * If the filter is null a base search is performed.
     * If both are null an error is thrown.
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
        try {
            X509Certificate cert = (X509Certificate) obj;
            String result = null;
            // form dn and filter for search.
            X500Name subjectDN = (X500Name) cert.getSubjectDN();

            logger.debug("LdapCertCompsMap: " + subjectDN);

            byte[] certbytes = cert.getEncoded();

            result = super.map(conn, subjectDN, certbytes);
            return result;
        } catch (CertificateEncodingException e) {
            logger.error(CMS.getLogMessage("PUBLISH_CANT_DECODE_CERT", e.toString()), e);
            throw new ELdapException(CMS.getUserMessage("CMS_LDAP_GET_DER_ENCODED_CERT_FAILED", e.toString()), e);
        } catch (ClassCastException e) {
            try {
                X509CRLImpl crl = (X509CRLImpl) obj;
                String result = null;
                X500Name issuerDN = (X500Name) crl.getIssuerDN();

                logger.warn("LdapCertCompsMap: " + issuerDN + ": " + e.getMessage(), e);

                byte[] crlbytes = crl.getEncoded();

                result = super.map(conn, issuerDN, crlbytes);
                return result;
            } catch (CRLException ex) {
                logger.error(CMS.getLogMessage("PUBLISH_CANT_DECODE_CRL", ex.toString()), ex);
                throw new ELdapException(CMS.getUserMessage("CMS_LDAP_GET_DER_ENCODED_CRL_FAILED", ex.toString()), ex);
            } catch (ClassCastException ex) {
                logger.warn(CMS.getLogMessage("PUBLISH_NOT_SUPPORTED_OBJECT"), ex);
                return null;
            }
        }
    }

    @Override
    public String map(LDAPConnection conn, IRequest req, Object obj)
            throws ELdapException {
        return map(conn, obj);
    }
}
