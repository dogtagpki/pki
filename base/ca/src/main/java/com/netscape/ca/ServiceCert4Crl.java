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
package com.netscape.ca;

import java.math.BigInteger;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.RevokedCertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ca.ECAException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.Request;

class ServiceCert4Crl implements IServant {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ServiceCert4Crl.class);

    public ServiceCert4Crl(CAService service) {
    }

    @Override
    public boolean service(Request request)
            throws EBaseException {
        // XXX Need to think passing as array.
        // XXX every implemented according to servlet.
        BigInteger revokedCertIds[] = request.getExtDataInBigIntegerArray(
                Request.REVOKED_CERT_RECORDS);
        if (revokedCertIds == null ||
                revokedCertIds.length == 0) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CERT4CRL_NO_ENTRY", request.getRequestId().toString()));
            throw new ECAException(CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_CLAREQ"));
        }

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository cr = engine.getCertificateRepository();

        CertRecord revokedCertRecs[] = new CertRecord[revokedCertIds.length];
        for (int i = 0; i < revokedCertIds.length; i++) {
            revokedCertRecs[i] = cr.readCertificateRecord(revokedCertIds[i]);
        }

        if (revokedCertRecs == null ||
                revokedCertRecs.length == 0 ||
                revokedCertRecs[0] == null) {
            // XXX should this be an error ?
            logger.error(CMS.getLogMessage("CMSCORE_CA_CERT4CRL_NO_ENTRY", request.getRequestId().toString()));
            throw new ECAException(CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_CLAREQ"));
        }

        CertRecord recordedCerts[] =
                new CertRecord[revokedCertRecs.length];
        String svcerrors[] = null;

        for (int i = 0; i < revokedCertRecs.length; i++) {
            try {
                // for CLA, record it into cert repost
                cr.addRevokedCertRecord(revokedCertRecs[i]);
                //				mService.revokeCert(crlentries[i]);
                recordedCerts[i] = revokedCertRecs[i];

                // inform all CRLIssuingPoints about revoked certificate

                for (CRLIssuingPoint ip : engine.getCRLIssuingPoints()) {
                    // form RevokedCertImpl
                    RevokedCertImpl rci =
                            new RevokedCertImpl(revokedCertRecs[i].getSerialNumber(),
                                    revokedCertRecs[i].getRevokedOn());

                    if (ip != null) {
                        ip.addRevokedCert(revokedCertRecs[i].getSerialNumber(), rci);
                    }
                }

            } catch (ECAException e) {
                logger.warn(CMS.getLogMessage("CMSCORE_CA_CERT4CRL_NO_REC", Integer.toString(i),
                        request.getRequestId().toString(), e.toString()), e);
                recordedCerts[i] = null;
                if (svcerrors == null) {
                    svcerrors = new String[recordedCerts.length];
                }
                svcerrors[i] = e.toString();
            }
        }
        //need to record which gets recorded and which failed...cfu
        //		request.set(Request.REVOKED_CERTS, revokedCerts);
        if (svcerrors != null) {
            request.setExtData(Request.SVCERRORS, svcerrors);
            throw new ECAException(CMS.getUserMessage("CMS_CA_CERT4CRL_FAILED"));
        }

        return true;
    }
}
