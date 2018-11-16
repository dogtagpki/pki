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
// (C) 2018 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.logging.event;

import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.SignedAuditEvent;

public class ComputeRandomDataRequestProcessedEvent extends SignedAuditEvent {

    private static final long serialVersionUID = 1L;

    public final static String SUCCESS =
            "LOGGING_SIGNED_AUDIT_COMPUTE_RANDOM_DATA_REQUEST_PROCESSED_SUCCESS";

    public final static String FAILURE =
            "LOGGING_SIGNED_AUDIT_COMPUTE_RANDOM_DATA_REQUEST_PROCESSED_FAILURE";

    public ComputeRandomDataRequestProcessedEvent(String messageID) {
        super(messageID);
    }

    public static ComputeRandomDataRequestProcessedEvent success(
            String status,
            String agentID) {

        ComputeRandomDataRequestProcessedEvent event = new ComputeRandomDataRequestProcessedEvent(SUCCESS);

        event.setAttribute("Outcome", ILogger.SUCCESS);
        event.setAttribute("Status", status);
        event.setAttribute("AgentID", agentID);

        return event;
    }

    public static ComputeRandomDataRequestProcessedEvent failure(
            String status,
            String agentID,
            String error) {

        ComputeRandomDataRequestProcessedEvent event = new ComputeRandomDataRequestProcessedEvent(FAILURE);

        event.setAttribute("Outcome", ILogger.FAILURE);
        event.setAttribute("Status", status);
        event.setAttribute("AgentID", agentID);
        event.setAttribute("Error", error);

        return event;
    }
}
