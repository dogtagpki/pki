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
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.logging.event;

import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequest;

public class CertRequestSuccessEvent extends AuditEvent {

    public final static String SIGNED_AUDIT_CERT_REQUEST_REASON =
            "requestNotes";

    public CertRequestSuccessEvent(
            String subjectID,
            String requesterID,
            String infoName) {

        this(subjectID, requesterID, infoName, ILogger.SIGNED_AUDIT_EMPTY_VALUE);
    }

    public CertRequestSuccessEvent(
            String subjectID,
            String requesterID,
            String infoName,
            String infoValue) {

        super(CERT_REQUEST_PROCESSED, new Object[]  {
                subjectID,
                ILogger.SUCCESS,
                requesterID,
                infoName,
                infoValue
        });
    }

    public CertRequestSuccessEvent(
            String subjectID,
            String requesterID,
            String infoName,
            IRequest request) {

        super(CERT_REQUEST_PROCESSED);

        setParameters(new Object[]  {
                subjectID,
                ILogger.SUCCESS,
                requesterID,
                infoName,
                auditInfoValue(request)
        });
    }

    /**
     * Signed Audit Log Info Value
     *
     * This method is called to obtain the "reason" for
     * a signed audit log message.
     * <P>
     *
     * @param request the actual request
     * @return reason string containing the signed audit log message reason
     */
    protected String auditInfoValue(IRequest request) {

        String reason = ILogger.SIGNED_AUDIT_EMPTY_VALUE;

        if (request != null) {
            // overwrite "reason" if and only if "info" != null
            String info =
                    request.getExtDataInString(SIGNED_AUDIT_CERT_REQUEST_REASON);

            if (info != null) {
                reason = info.trim();

                // overwrite "reason" if and only if "reason" is empty
                if (reason.equals("")) {
                    reason = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
                }
            }
        }

        return reason;
    }
}
