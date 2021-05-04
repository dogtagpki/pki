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

import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.SignedAuditEvent;

public class OCSPAddCARequestProcessedEvent extends SignedAuditEvent {

    private static final long serialVersionUID = 1L;

    public final static String OCSP_ADD_CA_REQUEST_PROCESSED =
            "LOGGING_SIGNED_AUDIT_OCSP_ADD_CA_REQUEST_PROCESSED";

    public OCSPAddCARequestProcessedEvent() {
        super(OCSP_ADD_CA_REQUEST_PROCESSED);
    }

    public static OCSPAddCARequestProcessedEvent createSuccessEvent(
            String subjectID,
            String caSubjectDN) {

        OCSPAddCARequestProcessedEvent event = new OCSPAddCARequestProcessedEvent();

        event.setAttribute("SubjectID", subjectID);
        event.setAttribute("Outcome", ILogger.SUCCESS);
        event.setAttribute("CASubjectDN", caSubjectDN);

        return event;
    }

    public static OCSPAddCARequestProcessedEvent createFailureEvent(
            String subjectID,
            String caSubjectDN) {

        OCSPAddCARequestProcessedEvent event = new OCSPAddCARequestProcessedEvent();

        event.setAttribute("SubjectID", subjectID);
        event.setAttribute("Outcome", ILogger.FAILURE);
        event.setAttribute("CASubjectDN", caSubjectDN);

        return event;
    }
}
