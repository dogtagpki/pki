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

public class RandomGenerationEvent extends SignedAuditEvent {

    private static final long serialVersionUID = 1L;

    private final static String RANDOM_GENERATION =
            "LOGGING_SIGNED_AUDIT_RANDOM_GENERATION";

    public RandomGenerationEvent() {
        super(RANDOM_GENERATION);
    }

    public static RandomGenerationEvent createSuccessEvent(
            String subjectID,
            String info) {

        RandomGenerationEvent event = new RandomGenerationEvent();

        event.setAttribute("SubjectID", subjectID);
        event.setAttribute("Outcome", ILogger.SUCCESS);
        event.setAttribute("Info", info);

        return event;
    }

    public static RandomGenerationEvent createFailureEvent(
            String subjectID,
            String info,
            String reason) {

        RandomGenerationEvent event = new RandomGenerationEvent();

        event.setAttribute("SubjectID", subjectID);
        event.setAttribute("Outcome", ILogger.FAILURE);
        event.setAttribute("Info", info);
        event.setAttribute("FailureReason", reason);

        return event;
    }
}
