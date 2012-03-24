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

import com.netscape.certsrv.base.EBaseException;

/**
 * This interface defines storage of request objects
 * in the local database.
 * <p>
 * 
 * @version $Revision$, $Date$
 */
public interface IRequestSubsystem {
    public static final String SUB_ID = "request";

    /**
     * Creates a new request queue.
     * (Currently unimplemented. Just use getRequestQueue to create
     * an in-memory queue.)
     * <p>
     * 
     * @param name The name of the queue object. This name can be used
     *            in getRequestQueue to retrieve the queue later.
     * @exception EBaseException failed to create request queue
     */
    public void createRequestQueue(String name)
            throws EBaseException;

    /**
     * Retrieves a request queue. This operation should only be done
     * once on each queue. For example, the RA subsystem should retrieve
     * its queue, and store it somewhere for use by related services, and
     * servlets.
     * <p>
     * WARNING: retrieving the same queue twice with result in multi-thread race conditions.
     * <p>
     * 
     * @param name
     *            the name of the request queue. (Ex: "ca" "ra")
     * @param p
     *            A policy enforcement module. This object is called to make
     *            adjustments to the request, and decide whether it needs agent
     *            approval.
     * @param s
     *            The service object. This object actually performs the request
     *            after it is finalized and approved.
     * @param n
     *            A notifier object (optional). The notify() method of this object
     *            is invoked when the request is completed (COMPLETE, REJECTED or
     *            CANCELED states).
     * @exception EBaseException failed to retrieve request queue
     */
    public IRequestQueue
            getRequestQueue(String name, int increment, IPolicy p, IService s, INotify n)
                    throws EBaseException;

    /**
     * Retrieves a request queue. This operation should only be done
     * once on each queue. For example, the RA subsystem should retrieve
     * its queue, and store it somewhere for use by related services, and
     * servlets.
     * <p>
     * WARNING: retrieving the same queue twice with result in multi-thread race conditions.
     * <p>
     * 
     * @param name
     *            the name of the request queue. (Ex: "ca" "ra")
     * @param p
     *            A policy enforcement module. This object is called to make
     *            adjustments to the request, and decide whether it needs agent
     *            approval.
     * @param s
     *            The service object. This object actually performs the request
     *            after it is finalized and approved.
     * @param n
     *            A notifier object (optional). The notify() method of this object
     *            is invoked when the request is completed (COMPLETE, REJECTED or
     *            CANCELED states).
     * @param pendingNotifier
     *            A notifier object (optional). Like the 'n' argument, except the
     *            notification happens if the request is made PENDING. May be the
     *            same as the 'n' argument if desired.
     * @exception EBaseException failed to retrieve request queue
     */
    public IRequestQueue
            getRequestQueue(String name, int increment, IPolicy p, IService s, INotify n,
                    INotify pendingNotifier)
                    throws EBaseException;
}
