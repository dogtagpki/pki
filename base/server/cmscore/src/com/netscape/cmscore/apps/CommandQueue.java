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

import javax.servlet.Servlet;

import com.netscape.certsrv.apps.ICommandQueue;
import com.netscape.certsrv.common.ICMSRequest;

/*---------------------------------------------------------------
 ** CommandQueue - Class
 */

/**
 * register and unregister proccess for clean shutdown
 */
public class CommandQueue implements Runnable, ICommandQueue {

    public static Hashtable<ICMSRequest, Servlet> mCommandQueue = new Hashtable<ICMSRequest, Servlet>();
    public static boolean mShuttingDown = false;

    /*-----------------------------------------------------------
     ** CommandQueue - Constructor
     */

    /**
     * Main constructor.
     */
    public CommandQueue() {

    } // CommandQueue

    /*-----------------------------------------------------------
     ** run
     */

    /**
     * Overrides Thread.run(), calls batchPublish().
     */
    public void run() {
        //int  priority = Thread.MIN_PRIORITY;
        //Thread.currentThread().setPriority(priority);
        /*-------------------------------------------------
         ** Loop until queue is empty
         */
        mShuttingDown = true;
        while (mCommandQueue.isEmpty() == false) {
            try {
                Thread.sleep(5 * 1000);
                //gcProcess();
            } catch (Exception e) {

            }
        }
    } // run

    public boolean registerProcess(ICMSRequest currentRequest, Servlet currentServlet) {
        if (mShuttingDown == false) {
            if ((currentServlet instanceof com.netscape.cms.servlet.base.CMSStartServlet) == false)
                mCommandQueue.put(currentRequest, currentServlet);
            return true;
        } else
            return false;

    }

    public void unRegisterProccess(Object currentRequest, Object currentServlet) {
        Enumeration<ICMSRequest> e = mCommandQueue.keys();

        while (e.hasMoreElements()) {
            Object thisRequest = e.nextElement();

            if (thisRequest.equals(currentRequest)) {
                if (mCommandQueue.get(currentRequest).equals(currentServlet))
                    mCommandQueue.remove(currentRequest);
            }
        }

    }
} // CommandQueue

