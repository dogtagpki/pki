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

public class OCSPRemoveCARequestProcessedEvent extends SignedAuditEvent {

    private static final long serialVersionUID = 1L;

    public final static String OCSP_REMOVE_CA_REQUEST_PROCESSED_SUCCESS =
            "LOGGING_SIGNED_AUDIT_OCSP_REMOVE_CA_REQUEST_PROCESSED_SUCCESS";

    public final static String OCSP_REMOVE_CA_REQUEST_PROCESSED_FAILURE =
            "LOGGING_SIGNED_AUDIT_OCSP_REMOVE_CA_REQUEST_PROCESSED_FAILURE";

    public OCSPRemoveCARequestProcessedEvent(String messageID) {
        super(messageID);
    }

    public static OCSPRemoveCARequestProcessedEvent createSuccessEvent(
            String subjectID,
            String caSubjectDN) {

        OCSPRemoveCARequestProcessedEvent event = new OCSPRemoveCARequestProcessedEvent(
                OCSP_REMOVE_CA_REQUEST_PROCESSED_SUCCESS);

        event.setAttribute("SubjectID", subjectID);
        event.setAttribute("Outcome", ILogger.SUCCESS);
        event.setAttribute("CASubjectDN", caSubjectDN);

        return event;
    }

    public static OCSPRemoveCARequestProcessedEvent createFailureEvent(
            String subjectID,
            String caSubjectDN) {

        OCSPRemoveCARequestProcessedEvent event = new OCSPRemoveCARequestProcessedEvent(
                OCSP_REMOVE_CA_REQUEST_PROCESSED_FAILURE);

        event.setAttribute("SubjectID", subjectID);
        event.setAttribute("Outcome", ILogger.FAILURE);
        event.setAttribute("CASubjectDN", caSubjectDN);

        return event;
    }
}
