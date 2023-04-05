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
package com.netscape.kra;

import java.math.BigInteger;

import org.dogtagpki.server.kra.KRAEngine;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.SecurityDataRecoveryProcessedEvent;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.request.Request;

/**
 * This implementation services SecurityData Recovery requests.
 */
public class SecurityDataRecoveryService implements IService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SecurityDataRecoveryService.class);

    private SecurityDataProcessor processor = null;

    public SecurityDataRecoveryService(KeyRecoveryAuthority kra) {
        processor = new SecurityDataProcessor(kra);
    }

    /**
     * Performs the service (such as certificate generation)
     * represented by this request.
     * <p>
     *
     * @param request
     *            The SecurityData recovery request that needs service. The service may use
     *            attributes stored in the request, and may update the
     *            values, or store new ones.
     * @return
     *         an indication of whether this request is still pending.
     *         'false' means the request will wait for further notification.
     * @exception EBaseException indicates major processing failure.
     */
    @Override
    public boolean serviceRequest(Request request)
            throws EBaseException {

        logger.debug("SecurityDataRecoveryService.serviceRequest()");

        // parameters for auditing
        String auditSubjectID = request.getExtDataInString(Request.ATTR_REQUEST_OWNER);
        BigInteger serialNumber = request.getExtDataInBigInteger("serialNumber");
        KeyId keyId = serialNumber != null ? new KeyId(serialNumber): null;
        RequestId requestID = request.getRequestId();
        String approvers = request.getExtDataInString(Request.ATTR_APPROVE_AGENTS);

        KRAEngine engine = KRAEngine.getInstance();
        Auditor auditor = engine.getAuditor();

        try {
            processor.recover(request);
            engine.getRequestRepository().updateRequest(request);
            auditor.log(new SecurityDataRecoveryProcessedEvent(
                    auditSubjectID,
                    ILogger.SUCCESS,
                    requestID,
                    keyId,
                    null,
                    approvers));
        } catch (EBaseException e) {
            auditor.log(new SecurityDataRecoveryProcessedEvent(
                    auditSubjectID,
                    ILogger.FAILURE,
                    requestID,
                    keyId,
                    e.getMessage(),
                    approvers));
            throw e;
        }
        return false;  //TODO: return true?
    }
}
