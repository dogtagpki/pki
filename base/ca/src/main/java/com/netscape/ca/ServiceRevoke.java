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

import org.mozilla.jss.netscape.security.x509.RevokedCertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ca.ECAException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.request.Request;

class ServiceRevoke implements IServant {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ServiceRevoke.class);

    private CAService mService;

    public ServiceRevoke(CAService service) {
        mService = service;
    }

    @Override
    public boolean service(Request request)
            throws EBaseException {
        boolean sendStatus = true;
        // XXX Need to think passing as array.
        // XXX every implemented according to servlet.
        RevokedCertImpl crlentries[] =
                request.getExtDataInRevokedCertArray(Request.CERT_INFO);

        if (crlentries == null ||
                crlentries.length == 0 ||
                crlentries[0] == null) {
            // XXX should this be an error ?
            logger.error(CMS.getLogMessage("CMSCORE_CA_CRL_NOT_FOUND", request.getRequestId().toString()));
            throw new ECAException(CMS.getUserMessage("CMS_CA_MISSING_INFO_IN_REVREQ"));
        }

        RevokedCertImpl revokedCerts[] =
                new RevokedCertImpl[crlentries.length];
        String svcerrors[] = null;

        for (int i = 0; i < crlentries.length; i++) {
            try {
                mService.revokeCert(crlentries[i], request.getRequestId().toString());
                revokedCerts[i] = crlentries[i];
            } catch (ECAException e) {
                logger.error(CMS.getLogMessage("CMSCORE_CA_CANNOT_REVOKE", Integer.toString(i), request
                        .getRequestId().toString(), e.toString()), e);
                revokedCerts[i] = null;
                if (svcerrors == null) {
                    svcerrors = new String[revokedCerts.length];
                }
                svcerrors[i] = e.toString();
            }
        }

        // #605941 - request.get(Request.CERT_INFO) store exact same thing
        // request.set(Request.REVOKED_CERTS, revokedCerts);

        // if clone ca, send revoked cert records to CLA
        if (CAService.mCLAConnector != null) {
            logger.debug(CMS.getLogMessage("CMSCORE_CA_CLONE_READ_REVOKED"));
            BigInteger revokedCertIds[] =
                    new BigInteger[revokedCerts.length];

            for (int i = 0; i < revokedCerts.length; i++) {
                revokedCertIds[i] = revokedCerts[i].getSerialNumber();
            }
            request.deleteExtData(Request.CERT_INFO);
            request.deleteExtData(Request.OLD_CERTS);
            request.setExtData(Request.REVOKED_CERT_RECORDS, revokedCertIds);

            logger.debug(CMS.getLogMessage("CMSCORE_CA_CLONE_READ_REVOKED_CONNECTOR"));

            request.setRequestType(Request.CLA_CERT4CRL_REQUEST);
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
            if (request.getExtDataInString(Request.ERROR) != null) {
                return sendStatus;
            }
        }

        if (svcerrors != null) {
            request.setExtData(Request.SVCERRORS, svcerrors);
            throw new ECAException(CMS.getUserMessage("CMS_CA_REVOKE_FAILED"));
        }

        logger.debug("serviceRevoke sendStatus=" + sendStatus);

        return sendStatus;
    }
}
