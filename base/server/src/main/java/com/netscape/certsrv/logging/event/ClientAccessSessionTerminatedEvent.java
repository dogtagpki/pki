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

public class ClientAccessSessionTerminatedEvent extends SignedAuditEvent {

    private static final long serialVersionUID = 1L;

    public final static String CLIENT_ACCESS_SESSION_TERMINATED =
            "LOGGING_SIGNED_AUDIT_CLIENT_ACCESS_SESSION_TERMINATED";

    public ClientAccessSessionTerminatedEvent(String messageID) {
        super(messageID);
    }

    public static ClientAccessSessionTerminatedEvent createEvent(
            String clientHost,
            String serverHost,
            String serverPort,
            String subjectID,
            String info) {

        ClientAccessSessionTerminatedEvent event = new ClientAccessSessionTerminatedEvent(
                CLIENT_ACCESS_SESSION_TERMINATED);

        event.setAttribute("ClientHost", clientHost);
        event.setAttribute("ServerHost", serverHost);
        event.setAttribute("ServerPort", serverPort);
        event.setAttribute("SubjectID", subjectID);
        event.setAttribute("Outcome", ILogger.SUCCESS);
        event.setAttribute("Info", info);

        return event;
    }
}
