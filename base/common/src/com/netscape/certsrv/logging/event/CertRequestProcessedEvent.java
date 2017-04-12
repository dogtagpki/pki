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

/**
 * LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED
 * - used when certificate request has just been through the approval process
 * SubjectID must be the UID of the agent who approves, rejects, or cancels
 *        the certificate request
 * ReqID must be the request ID
 * InfoName must be value "certificate" (in case of approval), "rejectReason"
 *        (in case of reject), or "cancelReason" (in case of cancel)
 * InfoValue must contain the certificate (in case of success), a reject reason in
 *        text, or a cancel reason in text
 *
 * LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED_5=
 *     <type=CERT_REQUEST_PROCESSED>:
 *     [AuditEvent=CERT_REQUEST_PROCESSED]
 *     [SubjectID={0}]
 *     [Outcome={1}]
 *     [ReqID={2}]
 *     [InfoName={3}]
 *     [InfoValue={4}]
 *     certificate request processed
 */
public class CertRequestProcessedEvent extends AuditEvent {

    private static final long serialVersionUID = 1L;

    public CertRequestProcessedEvent(
            String subjectID,
            String outcome,
            String requesterID,
            String infoName,
            String infoValue) {

        super(CERT_REQUEST_PROCESSED, new Object[]  {
                subjectID,
                outcome,
                requesterID,
                infoName,
                infoValue
        });
    }
}
