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

public class TokenPinResetEvent extends SignedAuditEvent {

    private static final long serialVersionUID = 1L;

    public final static String SUCCESS =
            "LOGGING_SIGNED_AUDIT_TOKEN_PIN_RESET_SUCCESS";

    public final static String FAILURE =
            "LOGGING_SIGNED_AUDIT_TOKEN_PIN_RESET_FAILURE";

    public TokenPinResetEvent(String messageID) {
        super(messageID);
    }

    public static TokenPinResetEvent success(
            String ip,
            String subjectID,
            String cuid,
            String tokenType,
            String appletVersion,
            String keyVersion) {

        TokenPinResetEvent event = new TokenPinResetEvent(SUCCESS);

        event.setAttribute("IP", ip);
        event.setAttribute("SubjectID", subjectID);
        event.setAttribute("CUID", cuid);
        event.setAttribute("Outcome", ILogger.SUCCESS);
        event.setAttribute("tokenType", tokenType);
        event.setAttribute("AppletVersion", appletVersion);
        event.setAttribute("KeyVersion", keyVersion);

        return event;
    }

    public static TokenPinResetEvent failure(
            String ip,
            String subjectID,
            String cuid,
            String tokenType,
            String appletVersion,
            String info) {

        TokenPinResetEvent event = new TokenPinResetEvent(FAILURE);

        event.setAttribute("IP", ip);
        event.setAttribute("SubjectID", subjectID);
        event.setAttribute("CUID", cuid);
        event.setAttribute("Outcome", ILogger.FAILURE);
        event.setAttribute("tokenType", tokenType);
        event.setAttribute("AppletVersion", appletVersion);
        event.setAttribute("Info", info);

        return event;
    }
}
