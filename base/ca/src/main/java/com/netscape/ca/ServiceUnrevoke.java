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
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ca.ECAException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.Request;

class ServiceUnrevoke implements IServant {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ServiceUnrevoke.class);

    private CAService mService;

    public ServiceUnrevoke(CAService service) {
        mService = service;
    }

    @Override
    public boolean service(Request request)
            throws EBaseException {
        boolean sendStatus = true;
        BigInteger oldSerialNo[] =
                request.getExtDataInBigIntegerArray(Request.OLD_SERIALS);

        if (oldSerialNo == null || oldSerialNo.length < 1) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_UNREVOKE_MISSING_SERIAL"));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_MISSING_SERIAL_NUMBER"));
        }

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository cr = engine.getCertificateRepository();

        String svcerrors[] = null;
        boolean needOldCerts = false;
        X509CertImpl oldCerts[] = request.getExtDataInCertArray(Request.OLD_CERTS);

        if (oldCerts == null || oldCerts.length < 1) {
            needOldCerts = true;
            oldCerts = new X509CertImpl[oldSerialNo.length];
        }

        for (int i = 0; i < oldSerialNo.length; i++) {
            try {
                if (oldSerialNo[i].compareTo(new BigInteger("0")) < 0) {
                    logger.error(CMS.getLogMessage("CMSCORE_CA_UNREVOKE_MISSING_SERIAL"));
                    throw new ECAException(
                            CMS.getUserMessage("CMS_CA_MISSING_SERIAL_NUMBER"));
                }
                if (needOldCerts) {
                    CertRecord certRec = cr.readCertificateRecord(oldSerialNo[i]);

                    oldCerts[i] = certRec.getCertificate();
                }
                mService.unrevokeCert(oldSerialNo[i], request.getRequestId().toString());
            } catch (ECAException e) {
                logger.warn(CMS.getLogMessage("CMSCORE_CA_UNREVOKE_FAILED", oldSerialNo[i].toString(),
                        request.getRequestId().toString()), e);
                if (svcerrors == null) {
                    svcerrors = new String[oldSerialNo.length];
                }
                svcerrors[i] = e.toString();
            }
        }

        // if clone ca, send unrevoked cert serials to CLA
        if (CAService.mCLAConnector != null) {
            request.setRequestType(Request.CLA_UNCERT4CRL_REQUEST);
            sendStatus = CAService.mCLAConnector.send(request);
            if (sendStatus && request.getExtDataInString(Request.ERROR) != null) {
                request.setExtData(Request.RESULT, Request.RES_SUCCESS);
                request.deleteExtData(Request.ERROR);
            } else {
                request.setExtData(Request.RESULT,
                        Request.RES_ERROR);
                request.setExtData(Request.ERROR,
                        new ECAException(CMS.getUserMessage("CMS_CA_SEND_CLA_REQUEST")));
                return sendStatus;
            }

        }

        if (needOldCerts) {
            request.setExtData(Request.OLD_CERTS, oldCerts);
        }

        if (svcerrors != null) {
            request.setExtData(Request.SVCERRORS, svcerrors);
            throw new ECAException(CMS.getUserMessage("CMS_CA_UNREVOKE_FAILED"));
        }

        return sendStatus;
    }
}
