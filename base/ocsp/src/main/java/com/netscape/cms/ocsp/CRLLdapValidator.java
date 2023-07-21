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
package com.netscape.cms.ocsp;

import java.security.cert.X509CRLEntry;
import java.util.Enumeration;

import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;

public class CRLLdapValidator implements SSLCertificateApprovalCallback {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CRLLdapValidator.class);

    private LDAPStore crlStore;



    public CRLLdapValidator(LDAPStore crlStore) {
        super();
        this.crlStore = crlStore;
    }


    @Override
    public boolean approve(X509Certificate certificate, ValidityStatus currentStatus) {
        logger.info("CRLLdapValidator: validate of peer's certificate for the connection " + certificate.getSubjectDN().toString());
        ICRLIssuingPointRecord pt = null;
        try {
            Enumeration<ICRLIssuingPointRecord> eCRL = crlStore.searchAllCRLIssuingPointRecord(-1);
            while (eCRL.hasMoreElements() && pt == null) {
                ICRLIssuingPointRecord tPt = eCRL.nextElement();
                logger.debug("CRLLdapValidator: CRL check issuer  " + tPt.getId());
                if(tPt.getId().equals(certificate.getIssuerDN().toString())) {
                    pt = tPt;
                }
            }
        } catch (EBaseException e) {
            logger.error("CRLLdapValidator: problem find CRL issuing point for " + certificate.getIssuerDN().toString());
            return false;
        }
        if (pt == null) {
            logger.error("CRLLdapValidator: CRL issuing point not found for " + certificate.getIssuerDN().toString());
            return false;
        }
        try {
            X509CRLImpl crl = new X509CRLImpl(pt.getCRL());
            X509CRLEntry crlentry = crl.getRevokedCertificate(certificate.getSerialNumber());

            if (crlentry == null) {
                if (crlStore.isNotFoundGood()) {
                    return true;
                }
            }
        } catch (Exception e) {
            logger.error("CRLLdapValidator: crl check error. " + e.getMessage());
        }
        logger.info("CRLLdapValidator: peer certificate not valid");
        return false;
    }

}
