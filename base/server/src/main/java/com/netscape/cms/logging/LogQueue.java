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

import java.util.Vector;

import com.netscape.certsrv.logging.LogEvent;
import com.netscape.certsrv.logging.LogEventListener;
import com.netscape.certsrv.logging.SignedAuditEvent;
import com.netscape.cmscore.apps.CMS;

/**
 * A class represents a log queue. A log queue
 * is a queue of pending log events to be dispatched
 * to a set of registered LogEventListeners.
 *
 * @author mzhao
 * @version $Revision$, $Date$
 */
public class LogQueue {

    private static LogQueue mLogQueue = new LogQueue();
    protected Vector<LogEventListener> mListeners = new Vector<>();

    /**
     * Constructs a log queue.
     */
    public LogQueue() {
    }

    public static LogQueue getLogQueue() {
        return mLogQueue;
    }

    /**
     * Initializes the log queue.
     */
    public void init() {
        mListeners.clear();

    }

    /**
     * Stops this log queue: shuts down all registered listeners.
     */
    public void shutdown() {
        for (int i = 0; i < mListeners.size(); i++) {
            LogEventListener listener = mListeners.elementAt(i);
            listener.shutdown();
        }
    }

    /**
     * Registers an event listener.
     *
     * @param listener The log event listener to be registered
     *            to this queue.
     */
    public void addLogEventListener(LogEventListener listener) {
        //Make sure we don't have duplicated listener
        if (!mListeners.contains(listener)) {
            mListeners.addElement(listener);
        }
    }

    /**
     * Removes an event listener.
     *
     * @param listener The log event listener to be removed from this queue.
     */
    public void removeLogEventListener(LogEventListener listener) {
        mListeners.removeElement(listener);
    }

    /**
     * Dispatch the log event to all registered log event listeners.
     *
     * @param event the log event
     */
    public void log(LogEvent event) {
        for (int i = 0; i < mListeners.size(); i++) {

            boolean isAudit = false;

            if( event instanceof SignedAuditEvent) {
                isAudit = true;
            }
            try {
                mListeners.elementAt(i).log(event);
            } catch (Exception e) {//Try to catch ELogException or possible RuntimeExceptions if thrown
                //Last resort log to the system for failed audit log attempt
                if(isAudit == true) {
                    System.err.println(CMS.getUserMessage("CMS_LOG_WRITE_FAILED", event.getEventType(), e.toString(), "Audit Event Failure!"));
                }
            }
        }
    }

    /**
     * Flushes log queue, flushes all registered listeners.
     * Messages should be written to their destination.
     */
    public void flush() {
        for (int i = 0; i < mListeners.size(); i++) {
            mListeners.elementAt(i).flush();
        }
    }
}
