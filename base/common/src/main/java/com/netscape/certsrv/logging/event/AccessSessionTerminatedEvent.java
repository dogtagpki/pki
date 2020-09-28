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

public class AccessSessionTerminatedEvent extends SignedAuditEvent {

    private static final long serialVersionUID = 1L;

    public final static String ACCESS_SESSION_TERMINATED =
            "LOGGING_SIGNED_AUDIT_ACCESS_SESSION_TERMINATED";

    public AccessSessionTerminatedEvent(String messageID) {
        super(messageID);
    }

    public static AccessSessionTerminatedEvent createEvent(
            String clientIP,
            String serverIP,
            String subjectID,
            String info) {

        AccessSessionTerminatedEvent event = new AccessSessionTerminatedEvent(
                ACCESS_SESSION_TERMINATED);

        event.setAttribute("ClientIP", clientIP);
        event.setAttribute("ServerIP", serverIP);
        event.setAttribute("SubjectID", subjectID);
        event.setAttribute("Outcome", ILogger.SUCCESS);
        event.setAttribute("Info", info);

        return event;
    }
}
