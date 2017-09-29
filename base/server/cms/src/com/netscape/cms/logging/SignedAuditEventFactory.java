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
import com.netscape.certsrv.logging.ILogEvent;
import com.netscape.certsrv.logging.LogSource;
import com.netscape.certsrv.logging.SignedAuditEvent;

/**
 * A log event object for handling system messages
 * <P>
 *
 * @author mikep
 * @author mzhao
 * @author cfu
 * @version $Revision$, $Date$
 */
public class SignedAuditEventFactory extends LogFactory {

    /**
     * Constructs a system event factory.
     */
    public SignedAuditEventFactory() {
    }

    /**
     * Creates an log event.
     *
     * @param source the subsystem ID who creates the log event
     * @param level the severity of the log event
     * @param multiline the log message has more than one line or not
     * @param msg the detail message of the log
     * @param params the parameters in the detail log message
     */
    public ILogEvent create(LogSource source,
            int level, boolean multiline, String msg, Object params[]) {

        String message = null;
        // assume msg format <type=...>:message
        String typeMessage = msg.trim();
        String eventType = null;
        int typeBegin = typeMessage.indexOf("<type=");

        if (typeBegin != -1) {
            // type is specified
            int colon = typeMessage.indexOf(">:");

            eventType = typeMessage.substring(typeBegin + 6, colon).trim();
            message = typeMessage.substring(colon + 2);
            //CMS.debug("SignedAuditEventFactory: create() message=" + message + "\n");
            CMS.debug("SignedAuditEventFactory: create() message created for eventType=" + eventType + "\n");

        } else {
            // no type specified
            message = typeMessage;
        }

        SignedAuditEvent event = new SignedAuditEvent();

        event.setEventType(eventType);
        event.setMessage(message);
        event.setParameters(params);
        event.setLevel(level);
        event.setSource(source);
        event.setMultiline(multiline);

        return event;
    }
}
