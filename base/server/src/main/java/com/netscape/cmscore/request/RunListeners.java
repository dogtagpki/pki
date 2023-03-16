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

import com.netscape.certsrv.request.RequestListener;

/**
 * The RunListeners class implements Runnable interface.
 * This class executes notification of registered listeners.
 */
public class RunListeners implements Runnable {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RunListeners.class);

    Request mRequest = null;
    Enumeration<RequestListener> mListeners = null;
    RequestNotifier mRequestNotifier;

    /**
     * RunListeners class constructor.
     *
     * @param r request
     * @param listeners list of listeners
     */
    public RunListeners(Request r, Enumeration<RequestListener> listeners) {
        mRequest = r;
        mListeners = listeners;
    }

    /**
     * RunListeners class constructor.
     *
     * @param requestNotifier request
     */
    public RunListeners(RequestNotifier requestNotifier) {
        mRequestNotifier = requestNotifier;
        mListeners = mRequestNotifier.getListeners();
    }

    /**
     * RunListeners thread implementation.
     */
    @Override
    public void run() {

        logger.info("RunListeners: Running listeners:");
        logger.info("RunListeners: - queue: " + (mRequestNotifier != null ? mRequestNotifier.getNumberOfRequests() : null));
        logger.info("RunListeners: - request: " + (mRequest != null ? mRequest.getRequestId().toHexString() : null));

        do {
            if (mRequestNotifier != null) {
                mRequest = mRequestNotifier.getRequest();
            }

            if (mListeners != null && mRequest != null) {
                logger.info("RunListeners: Processing request " + mRequest.getRequestId().toHexString());

                while (mListeners.hasMoreElements()) {
                    RequestListener l = mListeners.nextElement();
                    logger.info("RunListeners: Processing request " + mRequest.getRequestId().toHexString() + " with " + l.getClass().getSimpleName());
                    l.accept(mRequest);
                }

                if (mRequestNotifier != null) {
                    logger.info("RunListeners: Updating publishing status for request " + mRequest.getRequestId().toHexString());
                    mRequestNotifier.updatePublishingStatus(mRequest.getRequestId().toString());
                }
            }

            logger.info("RunListeners: Running listeners:");
            logger.info("RunListeners: - queue: " + (mRequestNotifier != null ? mRequestNotifier.getNumberOfRequests() : null));
            logger.info("RunListeners: - request: " + (mRequest != null ? mRequest.getRequestId().toHexString() : null));

            if (mRequestNotifier != null) {
                mListeners = mRequestNotifier.getListeners();
            }

        } while (mRequestNotifier != null && mRequestNotifier.getNumberOfRequests() > 0);

        if (mRequestNotifier != null) {
            mRequestNotifier.removeNotifierThread(Thread.currentThread());
        }
    }
}
