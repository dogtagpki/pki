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
package com.netscape.cms.request;

import java.util.Vector;

import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestScheduler;

/**
 * This class represents a request scheduler that prioritizes
 * the threads based on the request processing order.
 * The request that enters the request queue first should
 * be processed first.
 *
 * @version $Revision$, $Date$
 */
public class RequestScheduler implements IRequestScheduler {
    private Vector<Thread> mRequestThreads = new Vector<Thread>();

    /**
     * Request entered the request queue processing.
     *
     * @param r request
     */
    public synchronized void requestIn(IRequest r) {
        Thread current = Thread.currentThread();

        if (mRequestThreads.size() == 0) {
            current.setPriority(Thread.MAX_PRIORITY);
        }
        mRequestThreads.addElement(current);
    }

    /**
     * Request exited the request queue processing.
     *
     * @param r request
     */
    public synchronized void requestOut(IRequest r) {
        Thread current = Thread.currentThread();
        Thread first = mRequestThreads.elementAt(0);

        if (current.equals(first)) {
            // reprioritize
            try {
                Thread second = mRequestThreads.elementAt(1);

                second.setPriority(Thread.MAX_PRIORITY);
            } catch (Exception e) {
                // no second element; nothing to do
            }
        }
        mRequestThreads.removeElement(current);
    }
}
