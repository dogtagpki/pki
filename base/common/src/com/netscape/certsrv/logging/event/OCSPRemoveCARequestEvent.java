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

public class OCSPRemoveCARequestEvent extends SignedAuditEvent {

    private static final long serialVersionUID = 1L;

    public final static String OCSP_REMOVE_CA_REQUEST =
            "LOGGING_SIGNED_AUDIT_OCSP_REMOVE_CA_REQUEST";

    public OCSPRemoveCARequestEvent() {
        super(OCSP_REMOVE_CA_REQUEST);
    }

    public static OCSPRemoveCARequestEvent createSuccessEvent(
            String subjectID,
            String ca) {

        OCSPRemoveCARequestEvent event = new OCSPRemoveCARequestEvent();

        event.setAttribute("SubjectID", subjectID);
        event.setAttribute("Outcome", ILogger.SUCCESS);
        event.setAttribute("CA", ca);

        return event;
    }

    public static OCSPRemoveCARequestEvent createFailureEvent(
            String subjectID) {

        OCSPRemoveCARequestEvent event = new OCSPRemoveCARequestEvent();

        event.setAttribute("SubjectID", subjectID);
        event.setAttribute("Outcome", ILogger.FAILURE);

        return event;
    }
}
