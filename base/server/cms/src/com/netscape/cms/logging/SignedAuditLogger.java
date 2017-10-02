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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.logging;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.LogCategory;
import com.netscape.certsrv.logging.LogEvent;
import com.netscape.certsrv.logging.LogSource;
import com.netscape.certsrv.logging.SignedAuditEvent;

/**
 * A class represents certificate server logger
 * implementation.
 * <P>
 *
 * @author thomask
 * @author mzhao
 * @version $Revision$, $Date$
 */
public class SignedAuditLogger extends Logger {

    private final static SignedAuditLogger logger =
            new SignedAuditLogger();

    public SignedAuditLogger() {
        super(new SignedAuditEventFactory(),
                ILogger.EV_SIGNED_AUDIT,
                ILogger.S_SIGNED_AUDIT,
                ILogger.LL_SECURITY);
    }

    public static SignedAuditLogger getLogger() {
        return logger;
    }

    public void log(LogCategory category, LogSource source, int level, String message,
            Object params[], boolean multiline) {

        // create event
        SignedAuditEvent event = (SignedAuditEvent)create(
                category, source, level, message, params, multiline);

        // parse attributes in message
        int start = 0;
        while (start < message.length()) {

            // find [name=value]
            int i = message.indexOf("[", start);
            if (i < 0) break;

            int j = message.indexOf("=", i + 1);
            if (i < 0) {
                throw new RuntimeException("Missing equal sign: " + message);
            }

            // get attribute name
            String name = message.substring(i + 1, j);

            int k = message.indexOf("]", j + 1);
            if (k < 0) {
                throw new RuntimeException("Missing closing bracket: " + message);
            }

            // get attribute value
            String value = message.substring(j + 1, k);

            // store attribute in event
            event.setAttribute(name, value);

            start = k + 1;
        }

        mLogQueue.log(event);
    }

    public void log(LogEvent event) {

        String messageID = event.getMessage();
        Object[] params = event.getParameters();

        // generate audit log message that contains the parameters
        String message = CMS.getLogMessage(messageID, params);

        log(category, source, level, message, null, ILogger.L_SINGLELINE);
    }

    public void update(LogEvent event, LogSource source,
            int level, String message, Object params[], boolean multiline) {

        super.update(event, source, level, message, params, multiline);

        // split message into event type and actual message
        String eventType = null;
        message = message.trim();

        // message format: <type=...>:message
        int i = message.indexOf("<type=");

        if (i >= 0) { // message contains event type

            int j = message.indexOf(">:");
            eventType = message.substring(i + 6, j).trim();
            message = message.substring(j + 2).trim();

            CMS.debug("SignedAuditLogger: event " + eventType);
        }

        event.setEventType(eventType);
        event.setMessage(message);
    }
}
