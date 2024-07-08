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
package com.netscape.cmscore.apps;

import java.util.Enumeration;
import java.util.Hashtable;

import jakarta.servlet.Servlet;

import com.netscape.cms.servlet.common.CMSRequest;

/**
 * Command queue for registration and unregistration process for clean shutdown.
 */
public class CommandQueue implements Runnable {

    public static Hashtable<CMSRequest, Servlet> mCommandQueue = new Hashtable<>();
    public static boolean mShuttingDown = false;

    public CommandQueue() {
    }

    /**
     * Overrides Thread.run(), calls batchPublish().
     */
    @Override
    public void run() {
        //int  priority = Thread.MIN_PRIORITY;
        //Thread.currentThread().setPriority(priority);

        // Loop until queue is empty
        mShuttingDown = true;
        while (mCommandQueue.isEmpty() == false) {
            try {
                Thread.sleep(5 * 1000);
                //gcProcess();
            } catch (Exception e) {

            }
        }
    }

    /**
     * Registers a thread into the command queue.
     *
     * @param currentRequest request object
     * @param currentServlet servlet that serves the request object
     */
    public boolean registerProcess(CMSRequest currentRequest, Servlet currentServlet) {
        if (mShuttingDown) {
            return false;
        }
        mCommandQueue.put(currentRequest, currentServlet);
        return true;
    }

    /**
     * UnRegisters a thread from the command queue.
     *
     * @param currentRequest request object
     * @param currentServlet servlet that serves the request object
     */
    public void unRegisterProccess(Object currentRequest, Object currentServlet) {
        Enumeration<CMSRequest> e = mCommandQueue.keys();

        while (e.hasMoreElements()) {
            Object thisRequest = e.nextElement();

            if (thisRequest.equals(currentRequest)) {
                if (mCommandQueue.get(currentRequest).equals(currentServlet))
                    mCommandQueue.remove(currentRequest);
            }
        }
    }
}

