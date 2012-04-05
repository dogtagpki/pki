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
package com.netscape.certsrv.logging;

import java.util.Properties;

/**
 * An interface represents a log event factory. This
 * factory will be responsible for creating and returning ILogEvent objects
 * on demand.
 *
 * @version $Revision$, $Date$
 */
public interface ILogEventFactory {

    /**
     * Creates an event of a particular event type/class.
     *
     * @param evtClass The event type.
     * @param prop The resource bundle.
     * @param source The subsystem ID who creates the log event.
     * @param level The severity of the log event.
     * @param multiline The log message has more than one line or not.
     * @param msg The detail message of the log.
     * @param params The parameters in the detail log message.
     * @return The created ILogEvent object.
     */
    public ILogEvent create(int evtClass, Properties prop, int source,
            int level, boolean multiline, String msg, Object params[]);

    /**
     * Releases previously created event.
     *
     * @param event The log event.
     */
    public void release(ILogEvent event);
}
