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

import com.netscape.certsrv.logging.LogCategory;
import com.netscape.certsrv.logging.LogEvent;
import com.netscape.certsrv.logging.LogSource;

/**
 * A class representing a log event factory.
 * This factory will be responsible for creating and returning
 * ILogEvent objects on demand.
 */
public abstract class LogEventFactory {

    public LogEventFactory() {
    }

    public Logger createLogger(LogCategory category, LogSource source) {
        return new Logger(this, category, source);
    }

    /**
     * Creates a log event.
     */
    public abstract LogEvent create();

    /**
     * Releases previously created event.
     *
     * @param event The log event.
     */
    public void release(LogEvent event) {
        // do nothing
    }
}
