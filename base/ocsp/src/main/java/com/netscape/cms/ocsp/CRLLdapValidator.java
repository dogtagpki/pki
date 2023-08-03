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
// (C) 2023 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.ocsp;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRLEntry;
import java.util.Enumeration;

import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
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
        logger.info("CRLLdapValidator: validate of peer's certificate for the connection " + certificate.getSubjectDN());
        ICRLIssuingPointRecord pt = null;
        try {
            Enumeration<ICRLIssuingPointRecord> eCRL = crlStore.searchAllCRLIssuingPointRecord(-1);
            while (eCRL.hasMoreElements() && pt == null) {
                ICRLIssuingPointRecord tPt = eCRL.nextElement();
                logger.debug("CRLLdapValidator: CRL check issuer  " + tPt.getId());
                if(tPt.getId().equals(certificate.getIssuerDN().toString())) {
                    try {
                        X509CertImpl caCert = new X509CertImpl(tPt.getCACert());
                        X509CertImpl certToVerify = new X509CertImpl(certificate.getEncoded());
                        certToVerify.verify(caCert.getPublicKey(), Security.getProvider("Mozilla-JSS"));
                        pt = tPt;
                    } catch (CertificateException | InvalidKeyException | NoSuchAlgorithmException
                            | SignatureException e) {
                        logger.error("CRLLdapValidator: issuer certificate cannot verify the certificate signature." );
                    }
                }
            }
        } catch (EBaseException e) {
            logger.error("CRLLdapValidator: problem find CRL issuing point. " + e.getMessage(), e);
            return false;
        }
        if (pt == null) {
            logger.error("CRLLdapValidator: CRL issuing point not found for " + certificate.getIssuerDN());
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
            logger.error("CRLLdapValidator: crl check error. " + e.getMessage(), e);
        }
        logger.info("CRLLdapValidator: peer certificate not valid");
        return false;
    }

}
