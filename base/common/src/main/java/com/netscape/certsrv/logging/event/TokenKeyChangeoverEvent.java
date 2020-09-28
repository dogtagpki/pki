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

import com.netscape.certsrv.logging.SignedAuditEvent;

public class TokenKeyChangeoverEvent extends SignedAuditEvent {

    private static final long serialVersionUID = 1L;

    public final static String TOKEN_KEY_CHANGEOVER_SUCCESS =
            "LOGGING_SIGNED_AUDIT_TOKEN_KEY_CHANGEOVER_SUCCESS";

    public final static String TOKEN_KEY_CHANGEOVER_FAILURE =
            "LOGGING_SIGNED_AUDIT_TOKEN_KEY_CHANGEOVER_FAILURE";

    public TokenKeyChangeoverEvent(
            String messageID,
            String ip,
            String subjectID,
            String cuid,
            String msn,
            String outcome,
            String tokenType,
            String appletVersion,
            String oldKeyVersion,
            String newKeyVersion,
            String info) {

        super(messageID);

        setAttribute("IP", ip);
        setAttribute("SubjectID", subjectID);
        setAttribute("CUID", cuid);
        setAttribute("MSN", msn);
        setAttribute("Outcome", outcome);
        setAttribute("tokenType", tokenType);
        setAttribute("AppletVersion", appletVersion);
        setAttribute("oldKeyVersion", oldKeyVersion);
        setAttribute("newKeyVersion", newKeyVersion);
        setAttribute("Info", info);
    }
}
