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

import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.LogCategory;
import com.netscape.certsrv.logging.LogSource;

/**
 * A log event object for handling audit messages
 * <P>
 *
 * @author mikep
 * @author mzhao
 * @version $Revision$, $Date$
 */
public class AuditEventFactory extends LogFactory {

    /**
     * Constructs a audit event factory.
     */
    public AuditEventFactory() {
    }

    /**
     * Creates an log event.
     *
     * @param evtClass the event type
     * @param source the subsystem ID who creates the log event
     * @param level the severity of the log event
     * @param multiline the log message has more than one line or not
     * @param msg the detail message of the log
     * @param params the parameters in the detail log message
     */
    public ILogEvent create(LogCategory evtClass, LogSource source,
            int level, boolean multiline, String msg, Object params[]) {

        if (evtClass != ILogger.EV_AUDIT)
            return null;

        AuditEvent event = new AuditEvent(msg, params);

        event.setLevel(level);
        event.setSource(source);
        event.setMultiline(multiline);
        setProperties(null, event);

        return event;
    }
}
