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

public class TokenFormatEvent extends SignedAuditEvent {

    public final static String SUCCESS =
            "LOGGING_SIGNED_AUDIT_TOKEN_FORMAT_SUCCESS";

    public final static String FAILURE =
            "LOGGING_SIGNED_AUDIT_TOKEN_FORMAT_FAILURE";

    public TokenFormatEvent(String messageID) {
        super(messageID);
    }

    public static TokenFormatEvent success(
            String ip,
            String subjectID,
            String cuid,
            String msn,
            String tokenType,
            String appletVersion,
            String keyVersion) {

        TokenFormatEvent event = new TokenFormatEvent(SUCCESS);

        event.setAttribute("IP", ip);
        event.setAttribute("SubjectID", subjectID);
        event.setAttribute("CUID", cuid);
        event.setAttribute("MSN", msn);
        event.setAttribute("Outcome", ILogger.SUCCESS);
        event.setAttribute("tokenType", tokenType);
        event.setAttribute("AppletVersion", appletVersion);
        event.setAttribute("KeyVersion", keyVersion);

        return event;
    }

    public static TokenFormatEvent failure(
            String ip,
            String subjectID,
            String cuid,
            String msn,
            String tokenType,
            String appletVersion,
            String info) {

        TokenFormatEvent event = new TokenFormatEvent(FAILURE);

        event.setAttribute("IP", ip);
        event.setAttribute("SubjectID", subjectID);
        event.setAttribute("CUID", cuid);
        event.setAttribute("MSN", msn);
        event.setAttribute("Outcome", ILogger.FAILURE);
        event.setAttribute("tokenType", tokenType);
        event.setAttribute("AppletVersion", appletVersion);
        event.setAttribute("Info", info);

        return event;
    }
}
