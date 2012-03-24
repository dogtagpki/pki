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

/**
 * An interface represents a log queue. A log queue
 * is a queue of pending log events to be dispatched
 * to a set of registered ILogEventListeners.
 * 
 * @version $Revision$, $Date$
 */
public interface ILogQueue {

    /**
     * Dispatch the log event to all registered log event listeners.
     * 
     * @param evt the log event
     */
    public void log(ILogEvent evt);

    /**
     * Flushes log queue, flushes all registered listeners.
     * Messages should be written to their destination.
     */
    public void flush();

    /**
     * Registers an event listener.
     * 
     * @param listener The log event listener to be registered
     *            to this queue.
     */
    public void addLogEventListener(ILogEventListener listener);

    /**
     * Removes an event listener.
     * 
     * @param listener The log event listener to be removed from this queue.
     */
    public void removeLogEventListener(ILogEventListener listener);

    /**
     * Initializes the log queue.
     * <P>
     * 
     */
    public void init();

    /**
     * Stops this log queue:shuts down all registered log event listeners.
     * <P>
     */
    public void shutdown();

}
