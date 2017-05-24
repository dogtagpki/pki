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
import com.netscape.certsrv.request.RequestId;

public class SymKeyGenerationEvent extends AuditEvent {

    private static final long serialVersionUID = 1L;

    private static final String LOGGING_PROPERTY =
            "LOGGING_SIGNED_AUDIT_SYMKEY_GENERATION_REQUEST";

    public SymKeyGenerationEvent(
            String subjectID,
            String outcome,
            RequestId requestID,
            String clientKeyID) {

        super(LOGGING_PROPERTY);

        setParameters(new Object[] {
                subjectID,
                outcome,
                requestID,
                clientKeyID
        });
    }
}