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

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.LogEvent;
import com.netscape.certsrv.logging.event.SecurityDataRecoveryProcessedEvent;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;

/**
 * This implementation services SecurityData Recovery requests.
 * <p>
 *
 * @version $Revision$, $Date$
 */
public class SecurityDataRecoveryService implements IService {

    private static Logger signedAuditLogger = SignedAuditLogger.getLogger();

    private IKeyRecoveryAuthority kra = null;
    private SecurityDataProcessor processor = null;

    public SecurityDataRecoveryService(IKeyRecoveryAuthority kra) {
        this.kra = kra;
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
    public boolean serviceRequest(IRequest request)
            throws EBaseException {

        CMS.debug("SecurityDataRecoveryService.serviceRequest()");

        // parameters for auditing
        String auditSubjectID = request.getExtDataInString(IRequest.ATTR_REQUEST_OWNER);
        BigInteger serialNumber = request.getExtDataInBigInteger("serialNumber");
        KeyId keyId = serialNumber != null ? new KeyId(serialNumber): null;
        RequestId requestID = request.getRequestId();
        String approvers = request.getExtDataInString(IRequest.ATTR_APPROVE_AGENTS);

        try {
            processor.recover(request);
            kra.getRequestQueue().updateRequest(request);
            auditRecoveryRequestProcessed(
                    auditSubjectID,
                    ILogger.SUCCESS,
                    requestID,
                    keyId,
                    null,
                    approvers);
        } catch (EBaseException e) {
            auditRecoveryRequestProcessed(
                    auditSubjectID,
                    ILogger.FAILURE,
                    requestID,
                    keyId,
                    e.getMessage(),
                    approvers);
            throw e;
        }
        return false;  //TODO: return true?
    }

    protected void audit(LogEvent event) {
        signedAuditLogger.log(event);
    }

    private void audit(String msg) {
        signedAuditLogger.log(msg);
    }

    private void auditRecoveryRequestProcessed(String subjectID, String status, RequestId requestID,
            KeyId keyID, String reason, String recoveryAgents) {
        audit(new SecurityDataRecoveryProcessedEvent(
                subjectID,
                status,
                requestID,
                keyID,
                reason,
                recoveryAgents));
    }
}
