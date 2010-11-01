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


/**
 * IRequestNotifier interface defines methods to register listeners,
 *
 * @version $Revision$, $Date$
 */
public interface IRequestNotifier extends INotify {

    /**
     * Registers a request listener.
     *
     * @param listener listener to be registered
     */
    public void registerListener(IRequestListener listener);

    /**
     * Registers a request listener.
     *
     * @param name listener name
     * @param listener listener to be registered
     */
    public void registerListener(String name, IRequestListener listener);

    /**
     * Removes listener from the list of registered listeners.
     *
     * @param listener listener to be removed from the list
     */
    public void removeListener(IRequestListener listener);

    /**
     * Removes listener from the list of registered listeners.
     *
     * @param name listener name to be removed from the list
     */
    public void removeListener(String name);

    /**
     * Gets list of listener names.
     *
     * @return enumeration of listener names
     */
    public Enumeration getListenerNames();

    /**
     * Gets listener from the list of registered listeners.
     *
     * @param name listener name
     * @return listener
     */
    public IRequestListener getListener(String name);

    /**
     * Gets list of listeners.
     *
     * @return enumeration of listeners
     */
    public Enumeration getListeners();

    /**
     * Gets request from publishing queue.
     *
     * @return request
     */
    public IRequest getRequest();

    /**
     * Gets number of requests in publishing queue.
     *
     * @return number of requests in publishing queue
     */
    public int getNumberOfRequests();

    /**
     * Checks if publishing queue is enabled.
     *
     * @return true if publishing queue is enabled, false otherwise
     */
    public boolean isPublishingQueueEnabled();

    /**
     * Removes a notifier thread from the pool of publishing queue threads.
     *
     * @param notifierThread Thread
     */
    public void removeNotifierThread(Thread notifierThread);

    /**
     * Notifies all registered listeners about request.
     *
     * @param r request
     */
    public void addToNotify(IRequest r);

    /**
     * Sets publishing queue parameters.
     *
     * @param isPublishingQueueEnabled publishing queue switch
     * @param publishingQueuePriorityLevel publishing queue priority level
     * @param maxNumberOfPublishingThreads maximum number of publishing threads
     * @param publishingQueuePageSize publishing queue page size
     */
    public void setPublishingQueue (boolean isPublishingQueueEnabled,
                                    int publishingQueuePriorityLevel,
                                    int maxNumberOfPublishingThreads,
                                    int publishingQueuePageSize);

}
