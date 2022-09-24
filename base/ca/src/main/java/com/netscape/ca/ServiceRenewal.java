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

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.util.BigInt;
import org.mozilla.jss.netscape.security.x509.CertificateSerialNumber;
import org.mozilla.jss.netscape.security.x509.SerialNumber;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.ca.ECAException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.Request;

class ServiceRenewal implements IServant {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ServiceRenewal.class);

    private CAService mService;

    public ServiceRenewal(CAService service) {
        mService = service;
    }

    @Override
    public boolean service(Request request)
            throws EBaseException {
        // XXX if one fails should all fail ? - can't backtrack.
        X509CertInfo certinfos[] =
                request.getExtDataInCertInfoArray(Request.CERT_INFO);

        if (certinfos == null || certinfos[0] == null) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CERT_REQUEST_NOT_FOUND", request.getRequestId().toString()));
            throw new ECAException(
                    CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_RENEWREQ"));
        }

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository cr = engine.getCertificateRepository();

        X509CertImpl issuedCerts[] = new X509CertImpl[certinfos.length];

        for (int j = 0; j < issuedCerts.length; j++)
            issuedCerts[j] = null;
        String svcerrors[] = new String[certinfos.length];

        for (int k = 0; k < svcerrors.length; k++)
            svcerrors[k] = null;
        String rid = request.getRequestId().toString();

        for (int i = 0; i < certinfos.length; i++) {
            try {
                // get old serial number.
                SerialNumber serialnum = null;

                try {
                    CertificateSerialNumber serialno = (CertificateSerialNumber)
                            certinfos[i].get(X509CertInfo.SERIAL_NUMBER);

                    if (serialno == null) {
                        logger.error(CMS.getLogMessage("CMSCORE_CA_NULL_SERIAL_NUMBER"));
                        throw new ECAException(
                                CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_RENEWREQ"));
                    }
                    serialnum = (SerialNumber)
                            serialno.get(CertificateSerialNumber.NUMBER);

                } catch (IOException e) {
                    String message = CMS.getLogMessage("CMSCORE_CA_ERROR_GET_CERT", e.toString());
                    logger.error(message, e);
                    throw new ECAException(
                            CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_RENEWREQ"));

                } catch (CertificateException e) {
                    String message = CMS.getLogMessage("CMSCORE_CA_ERROR_GET_CERT", e.toString());
                    logger.error(message, e);
                    throw new ECAException(
                            CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_RENEWREQ"));
                }

                if (serialnum == null) {
                    logger.error(CMS.getLogMessage("CMSCORE_CA_ERROR_GET_CERT", ""));
                    throw new ECAException(
                            CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_RENEWREQ"));
                }
                BigInt serialnumBigInt = serialnum.getNumber();
                BigInteger oldSerialNo = serialnumBigInt.toBigInteger();

                // get cert record
                CertRecord certRecord = cr.readCertificateRecord(oldSerialNo);

                if (certRecord == null) {
                    logger.error(CMS.getLogMessage("CMSCORE_CA_NOT_FROM_CA", oldSerialNo.toString()));
                    svcerrors[i] = new ECAException(
                            CMS.getUserMessage("CMS_CA_CANT_FIND_CERT_SERIAL",
                                    oldSerialNo.toString())).toString();
                    continue;
                }

                // check if cert has been revoked.
                String certStatus = certRecord.getStatus();

                if (certStatus.equals(CertRecord.STATUS_REVOKED) ||
                        certStatus.equals(CertRecord.STATUS_REVOKED_EXPIRED)) {
                    logger.error(CMS.getLogMessage("CMSCORE_CA_RENEW_REVOKED", oldSerialNo.toString()));
                    svcerrors[i] = new ECAException(
                            CMS.getUserMessage("CMS_CA_CANNOT_RENEW_REVOKED_CERT",
                                    "0x" + oldSerialNo.toString(16))).toString();
                    continue;
                }

                // check if cert has already been renewed.
                MetaInfo metaInfo = certRecord.getMetaInfo();

                if (metaInfo != null) {
                    String renewed = (String) metaInfo.get(CertRecord.META_RENEWED_CERT);

                    if (renewed != null) {
                        BigInteger serial = new BigInteger(renewed);
                        X509CertImpl cert = cr.getX509Certificate(serial);

                        if (cert == null) {
                            // something wrong
                            logger.error(CMS.getLogMessage("CMSCORE_CA_MISSING_RENEWED", serial.toString()));
                            svcerrors[i] = new ECAException(
                                    CMS.getUserMessage("CMS_CA_ERROR_GETTING_RENEWED_CERT",
                                            oldSerialNo.toString(), serial.toString())).toString();
                            continue;
                        }
                        // get cert record
                        CertRecord cRecord = cr.readCertificateRecord(serial);

                        if (cRecord == null) {
                            logger.error(CMS.getLogMessage("CMSCORE_CA_NOT_FROM_CA", serial.toString()));
                            svcerrors[i] = new ECAException(
                                    CMS.getUserMessage("CMS_CA_CANT_FIND_CERT_SERIAL",
                                            serial.toString())).toString();
                            continue;
                        }
                        // Check renewed certificate already REVOKED or EXPIRED
                        String status = cRecord.getStatus();

                        if (status.equals(CertRecord.STATUS_REVOKED) ||
                                status.equals(CertRecord.STATUS_REVOKED_EXPIRED)) {
                            logger.debug("It is already revoked or Expired !!!");
                        } // it is still new ... So just return this certificate to user
                        else {
                            logger.debug("It is still new !!!");
                            issuedCerts[i] = cert;
                            continue;
                        }
                    }
                }

                // issue the cert.
                issuedCerts[i] =
                        mService.issueX509Cert(rid, certinfos[i], true, oldSerialNo);
                mService.storeX509Cert(rid, issuedCerts[i], true, oldSerialNo);
            } catch (ECAException e) {
                svcerrors[i] = e.toString();
                logger.warn(CMS.getLogMessage("CMSCORE_CA_CANNOT_RENEW", Integer.toString(i), request
                        .getRequestId().toString()), e);
            }
        }

        // always set issued certs regardless of error.
        request.setExtData(Request.ISSUED_CERTS, issuedCerts);

        // set and throw error if any.
        int l;

        for (l = svcerrors.length - 1; l >= 0 && svcerrors[l] == null; l--)
            ;
        if (l >= 0) {
            request.setExtData(Request.SVCERRORS, svcerrors);
            logger.error(CMS.getLogMessage("CMSCORE_CA_NO_RENEW", request.getRequestId().toString()));
            throw new ECAException(CMS.getUserMessage("CMS_CA_RENEW_FAILED"));
        }
        return true;
    }
}
