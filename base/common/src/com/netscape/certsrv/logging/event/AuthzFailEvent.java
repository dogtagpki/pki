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

import com.netscape.certsrv.logging.SignedAuditEvent;

public class AuthzFailEvent extends SignedAuditEvent {

    private static final long serialVersionUID = 1L;

    public final static String AUTHZ_FAIL =
            "LOGGING_SIGNED_AUDIT_AUTHZ_FAIL";

    public AuthzFailEvent(
            String subjectID,
            String outcome,
            String aclResource,
            String operation) {

        super(AUTHZ_FAIL);

        setAttribute("SubjectID", subjectID);
        setAttribute("Outcome", outcome);
        setAttribute("aclResource", aclResource);
        setAttribute("Op", operation);
    }

    public AuthzFailEvent(
            String subjectID,
            String outcome,
            String aclResource,
            String operation,
            String info) {

        super(AUTHZ_FAIL);

        setAttribute("SubjectID", subjectID);
        setAttribute("Outcome", outcome);
        setAttribute("aclResource", aclResource);
        setAttribute("Op", operation);
        setAttribute("Info", info);
    }
}
