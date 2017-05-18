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

import java.math.BigInteger;

import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;

public class DeltaCRLGenerationEvent extends AuditEvent {

    private static final long serialVersionUID = 1L;

    public final static String LOGGING_PROPERTY =
            "LOGGING_SIGNED_AUDIT_DELTA_CRL_GENERATION";

    public DeltaCRLGenerationEvent() {
        super(LOGGING_PROPERTY);
    }

    public static DeltaCRLGenerationEvent createSuccessEvent(
            String subjectID,
            BigInteger crlNumber) {

        DeltaCRLGenerationEvent event = new DeltaCRLGenerationEvent();

        event.setAttribute("CRLnum", crlNumber);

        event.setParameters(new Object[] {
                subjectID,
                ILogger.SUCCESS,
                event.getAttributeList()
        });

        return event;
    }

    public static DeltaCRLGenerationEvent createSuccessEvent(
            String subjectID,
            String info) {

        DeltaCRLGenerationEvent event = new DeltaCRLGenerationEvent();

        event.setAttribute("Info", info);

        event.setParameters(new Object[] {
                subjectID,
                ILogger.SUCCESS,
                event.getAttributeList()
        });

        return event;
    }

    public static DeltaCRLGenerationEvent createFailureEvent(
            String subjectID,
            String reason) {

        DeltaCRLGenerationEvent event = new DeltaCRLGenerationEvent();

        event.setAttribute("FailureReason", reason);

        event.setParameters(new Object[] {
                subjectID,
                ILogger.FAILURE,
                event.getAttributeList()
        });

        return event;
    }
}
