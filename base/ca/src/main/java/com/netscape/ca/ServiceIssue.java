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
import java.security.cert.X509Certificate;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ca.ECAException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.Request;

class ServiceIssue implements IServant {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ServiceIssue.class);

    private CAService mService;

    public ServiceIssue(CAService service) {
        mService = service;
    }

    @Override
    public boolean service(Request request)
            throws EBaseException {
        // XXX This is ugly. should associate attributes with
        // request types, not policy.
        // XXX how do we know what to look for in request ?

        boolean requestContentsAreNull = request.getExtDataInCertInfoArray(Request.CERT_INFO) == null;
        return !requestContentsAreNull && serviceX509(request);
    }

    public boolean serviceX509(Request request)
            throws EBaseException {
        // XXX This is ugly. should associate attributes with
        // request types, not policy.
        // XXX how do we know what to look for in request ?
        X509CertInfo certinfos[] =
                request.getExtDataInCertInfoArray(Request.CERT_INFO);

        if (certinfos == null || certinfos[0] == null) {
            logger.error(CMS.getLogMessage("CMSCORE_CA_CERT_REQUEST_NOT_FOUND", request.getRequestId().toString()));
            throw new ECAException(CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_ISSUEREQ"));
        }

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository cr = engine.getCertificateRepository();

        String challengePassword =
                request.getExtDataInString(CAService.CHALLENGE_PHRASE);

        X509CertImpl[] certs = new X509CertImpl[certinfos.length];
        String rid = request.getRequestId().toString();
        int i;

        for (i = 0; i < certinfos.length; i++) {
            try {
                certs[i] = mService.issueX509Cert(rid, certinfos[i]);
            } catch (EBaseException e) {
                logger.error(CMS.getLogMessage("CMSCORE_CA_ISSUE_ERROR", Integer.toString(i), rid, e.toString()), e);
                throw e;
            }
        }
        String crmfReqId = request.getExtDataInString(Request.CRMF_REQID);
        EBaseException ex = null;

        for (i = 0; i < certs.length; i++) {
            try {
                mService.storeX509Cert(rid, certs[i], crmfReqId, challengePassword);
            } catch (EBaseException e) {
                String message = CMS.getLogMessage("CMSCORE_CA_STORE_ERROR", Integer.toString(i), rid, e.toString());
                logger.warn(message, e);
                ex = e; // save to throw later.
                break;
            }
        }
        if (ex != null) {
            for (int j = 0; j < i; j++) {
                // delete the stored cert records from the database.
                // we issue all or nothing.
                BigInteger serialNo =
                        ((X509Certificate) certs[i]).getSerialNumber();

                try {
                    cr.deleteCertificateRecord(serialNo);
                } catch (EBaseException e) {
                    logger.warn(CMS.getLogMessage("CMSCORE_CA_DELETE_CERT_ERROR", serialNo.toString(), e.toString()), e);
                }
            }
            throw ex;
        }

        request.setExtData(Request.ISSUED_CERTS, certs);

        return true;
    }
}
