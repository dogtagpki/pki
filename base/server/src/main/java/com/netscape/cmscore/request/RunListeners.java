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
package com.netscape.cmscore.request;

import java.util.Enumeration;

import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.certsrv.request.IRequestNotifier;

/**
 * The RunListeners class implements Runnable interface.
 * This class executes notification of registered listeners.
 */
public class RunListeners implements Runnable {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RunListeners.class);

    IRequest mRequest = null;
    Enumeration<IRequestListener> mListeners = null;
    IRequestNotifier mRequestNotifier = null;

    /**
     * RunListeners class constructor.
     *
     * @param r request
     * @param listeners list of listeners
     */
    public RunListeners(IRequest r, Enumeration<IRequestListener> listeners) {
        mRequest = r;
        mListeners = listeners;
    }

    /**
     * RunListeners class constructor.
     *
     * @param requestNotifier request
     */
    public RunListeners(IRequestNotifier requestNotifier) {
        mRequestNotifier = requestNotifier;
        mListeners = mRequestNotifier.getListeners();
    }

    /**
     * RunListeners thread implementation.
     */
    @Override
    public void run() {
        logger.debug("RunListeners::"
                + ((mRequestNotifier != null && mRequestNotifier.getNumberOfRequests() > 0) ? " Queue: "
                        + mRequestNotifier.getNumberOfRequests() : " noQueue") +
                  " " + ((mRequest != null) ? " SingleRequest" : " noSingleRequest"));
        do {
            if (mRequestNotifier != null)
                mRequest = mRequestNotifier.getRequest();
            if (mListeners != null && mRequest != null) {
                while (mListeners.hasMoreElements()) {
                    IRequestListener l = mListeners.nextElement();
                    logger.debug("RunListeners: IRequestListener = " + l.getClass().getName());
                    l.accept(mRequest);
                }
                if (mRequestNotifier != null) {
                    logger.debug("RunListeners: mRequest = " + mRequest.getRequestId().toString());
                    mRequestNotifier.updatePublishingStatus(mRequest.getRequestId().toString());
                }
            }
            logger.debug("RunListeners: "
                    + ((mRequestNotifier != null && mRequestNotifier.getNumberOfRequests() > 0) ? " Queue: "
                            + mRequestNotifier.getNumberOfRequests() : " noQueue") +
                      " " + ((mRequest != null) ? " SingleRequest" : " noSingleRequest"));
            if (mRequestNotifier != null)
                mListeners = mRequestNotifier.getListeners();
        } while (mRequestNotifier != null && mRequestNotifier.getNumberOfRequests() > 0);

        if (mRequestNotifier != null)
            mRequestNotifier.removeNotifierThread(Thread.currentThread());
    }
}
