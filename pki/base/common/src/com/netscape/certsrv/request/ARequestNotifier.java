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
package com.netscape.certsrv.request;


import java.util.*;

import com.netscape.certsrv.request.*;
import com.netscape.certsrv.logging.ILogger;


/**
 * The ARequestNotifier class implements the IRequestNotifier interface,
 * which notifies all registered request listeners.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class ARequestNotifier implements IRequestNotifier {
    Hashtable mListeners = new Hashtable();

    /**
     * Registers a request listener.
     *
     * @param listener listener to be registered
     */
    public void registerListener(IRequestListener listener) {
        // XXX should check for duplicates here or allow listeners
        // to register twice and call twice ? 
        mListeners.put(listener.getClass().getName(), listener);
    }

    /**
     * Registers a request listener.
     *
     * @param name listener name
     * @param listener listener to be registered
     */
    public void registerListener(String name, IRequestListener listener) {
        mListeners.put(name, listener);
    }

    /**
     * Removes listener from the list of registered listeners.
     *
     * @param listener listener to be removed from the list
     */
    public void removeListener(IRequestListener listener) {
        // XXX should check for duplicates here or allow listeners
        // to register twice and call twice ? 
        mListeners.remove(listener.getClass().getName());
    }

    /**
     * Gets list of listener names.
     *
     * @return enumeration of listener names
     */
    public Enumeration getListenerNames() {
        return mListeners.keys();
    }

    /**
     * Removes listener from the list of registered listeners.
     *
     * @param name listener name to be removed from the list
     */
    public void removeListener(String name) {
        mListeners.remove(name);
    }

    /**
     * Gets listener from the list of registered listeners.
     *
     * @param name listener name
     * @return listener
     */
    public IRequestListener getListener(String name) {
        return (IRequestListener) mListeners.get(name);
    }

    /**
     * Notifies all registered listeners about request.
     *
     * @param r request
     */
    public void notify(IRequest r) {
        // spawn a seperate thread to call the listeners and return.
        try {
            new Thread(new RunListeners(r, mListeners.elements())).start();
        } catch (Throwable e) {

            /*
             CMS.getLogger().log(
             ILogger.EV_SYSTEM, ILogger.S_REQQUEUE, ILogger.LL_FAILURE, 
             "Could not run listeners for request " + r.getRequestId() +
             ". Error " + e + ";" + e.getMessage());
             */
        }
    }
}


/**
 * The RunListeners class implements Runnable interface.
 * This class executes notification of registered listeners.
 */
class RunListeners implements Runnable {
    IRequest mRequest = null;
    Enumeration mListeners = null;

    /**
     * RunListeners class constructor.
     *
     * @param r request
     * @param listeners list of listeners
     */
    public RunListeners(IRequest r, Enumeration listeners) {
        mRequest = r;
        mListeners = listeners;
    }

    /**
     * RunListeners thread implementation.
     */
    public void run() {
        if (mListeners != null) {
            while (mListeners.hasMoreElements()) {
                IRequestListener l = 
                    (IRequestListener) mListeners.nextElement();

                l.accept(mRequest);
            }
        }
    }
}
