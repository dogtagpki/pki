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
package com.netscape.cmscore.logging;

import java.util.Vector;

import com.netscape.certsrv.logging.ELogException;
import com.netscape.certsrv.logging.ILogEvent;
import com.netscape.certsrv.logging.ILogEventListener;
import com.netscape.certsrv.logging.ILogQueue;

/**
 * A class represents a log queue.
 * <P>
 *
 * @author mzhao
 * @version $Revision$, $Date$
 */
public class LogQueue implements ILogQueue {

    private static LogQueue mLogQueue = new LogQueue();
    protected Vector<ILogEventListener> mListeners = null;

    /**
     * Constructs a log queue.
     */
    public LogQueue() {
    }

    public static ILogQueue getLogQueue() {
        return mLogQueue;
    }

    /**
     * Initializes the log queue.
     * <P>
     *
     */
    public void init() {
        mListeners = new Vector<ILogEventListener>();

    }

    /**
     * Stops this log queue: shuts down all registered listeners
     * <P>
     */
    public void shutdown() {
        if (mListeners == null)
            return;
        for (int i = 0; i < mListeners.size(); i++) {
            mListeners.elementAt(i).shutdown();
        }
    }

    /**
     * Adds an event listener.
     *
     * @param listener the log event listener
     */
    public void addLogEventListener(ILogEventListener listener) {
        //Make sure we don't have duplicated listener
        if (!mListeners.contains(listener))
            mListeners.addElement(listener);
    }

    /**
     * Removes an event listener.
     *
     * @param listener the log event listener
     */
    public void removeLogEventListener(ILogEventListener listener) {
        mListeners.removeElement(listener);
    }

    /**
     * Logs an event, and notifies logger to reuse the event.
     *
     * @param event the log event
     */
    public void log(ILogEvent event) {
        if (mListeners == null)
            return;
        for (int i = 0; i < mListeners.size(); i++) {
            try {
                mListeners.elementAt(i).log(event);
            } catch (ELogException e) {
                // Raidzilla Bug #57592:  Don't display potentially
                //                        incorrect log message.
                // ConsoleError.send(new SystemEvent(CMS.getUserMessage("CMS_LOG_EVENT_FAILED",
                //          event.getEventType(), e.toString())));

                // Don't do this again.
                removeLogEventListener(mListeners.elementAt(i));
            }
        }
    }

    /**
     * Flushes the log buffers (if any)
     */
    public void flush() {
        for (int i = 0; i < mListeners.size(); i++) {
            mListeners.elementAt(i).flush();
        }
    }
}
