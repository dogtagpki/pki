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

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRLEntry;
import java.util.Arrays;
import java.util.Enumeration;

import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.x509.AuthorityKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.KeyIdentifier;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;
import org.mozilla.jss.netscape.security.x509.SubjectKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.dbs.CRLIssuingPointRecord;

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
        CRLIssuingPointRecord pt = null;
        try {
            X509CertImpl peerCert = new X509CertImpl(certificate.getEncoded());
            Enumeration<CRLIssuingPointRecord> eCRL = crlStore.searchAllCRLIssuingPointRecord(-1);
            AuthorityKeyIdentifierExtension peerAKIExt = (AuthorityKeyIdentifierExtension) peerCert.getExtension(PKIXExtensions.AuthorityKey_Id.toString());
            if(peerAKIExt == null) {
                logger.error("CRLLdapValidator: the certificate has not Authority Key Identifier Extension. CRL verification cannot be done.");
                return false;
            }
            while (eCRL.hasMoreElements() && pt == null) {
                CRLIssuingPointRecord tPt = eCRL.nextElement();
                logger.debug("CRLLdapValidator: CRL check issuer  " + tPt.getId());
                X509CertImpl caCert = new X509CertImpl(tPt.getCACert());
                try {
                    SubjectKeyIdentifierExtension caAKIExt = (SubjectKeyIdentifierExtension) caCert.getExtension(PKIXExtensions.SubjectKey_Id.toString());
                    if(caAKIExt == null) {
                        logger.error("CRLLdapValidator: signing certificate missing Subject Key Identifier. Skip CA " + caCert.getName());
                        continue;
                    }

                    KeyIdentifier caSKIId = (KeyIdentifier) caAKIExt.get(SubjectKeyIdentifierExtension.KEY_ID);
                    KeyIdentifier peerAKIId = (KeyIdentifier) peerAKIExt.get(AuthorityKeyIdentifierExtension.KEY_ID);
                    if(Arrays.equals(caSKIId.getIdentifier(), peerAKIId.getIdentifier())) {
                        pt = tPt;
                    }
                } catch (IOException e) {
                    logger.error("CRLLdapValidator: problem extracting key from SKI/AKI");
                }
            }
        } catch (EBaseException | CertificateException e) {
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
        logger.error("CRLLdapValidator: peer certificate not valid");
        return false;
    }

}
