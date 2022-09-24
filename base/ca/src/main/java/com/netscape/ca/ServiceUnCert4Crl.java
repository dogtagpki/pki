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

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ca.ECAException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.Request;

class ServiceUnCert4Crl implements IServant {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ServiceUnCert4Crl.class);

    public ServiceUnCert4Crl(CAService service) {
    }

    @Override
    public boolean service(Request request)
            throws EBaseException {
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

        for (int i = 0; i < oldSerialNo.length; i++) {
            try {
                cr.deleteCertificateRecord(oldSerialNo[i]);

                // inform all CRLIssuingPoints about unrevoked certificate

                for (CRLIssuingPoint ip : engine.getCRLIssuingPoints()) {
                    if (ip != null) {
                        ip.addUnrevokedCert(oldSerialNo[i]);
                    }
                }
            } catch (EBaseException e) {
                logger.warn(CMS.getLogMessage("CMSCORE_CA_DELETE_CERT_ERROR", oldSerialNo[i].toString(), e.toString()), e);
                if (svcerrors == null) {
                    svcerrors = new String[oldSerialNo.length];
                }
                svcerrors[i] = e.toString();
            }

        }

        if (svcerrors != null) {
            request.setExtData(Request.SVCERRORS, svcerrors);
            throw new ECAException(CMS.getUserMessage("CMS_CA_UNCERT4CRL_FAILED"));
        }

        return true;
    }
}
