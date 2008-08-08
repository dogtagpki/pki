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

import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.logging.ILogger;

/**
 * The ARequestNotifier class implements the IRequestNotifier interface,
 * which notifies all registered request listeners.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class ARequestNotifier implements IRequestNotifier {
    private Hashtable mListeners = new Hashtable();
    private Vector mNotifierThreads = new Vector();
    private Vector mRequests = new Vector();
    private int mMaxThreads = 1;
    private boolean mIsPublishingQueueEnabled = false;
    private int mPublishingQueuePriorityLevel = 2;
    private int mPublishingQueuePriority = 0;


    public ARequestNotifier() {
        mPublishingQueuePriority = Thread.currentThread().getPriority();
    }

    public ARequestNotifier(boolean isPublishingQueueEnabled, int publishingQueuePriorityLevel) {
        mIsPublishingQueueEnabled = isPublishingQueueEnabled;
        mPublishingQueuePriorityLevel = publishingQueuePriorityLevel;

        // Publishing Queue Priority Levels:  2 - maximum, 1 - raised, 0 - normal
        if (publishingQueuePriorityLevel > 1) {
            mPublishingQueuePriority = Thread.MAX_PRIORITY;
        } else if (publishingQueuePriorityLevel > 0) {
            mPublishingQueuePriority = (Thread.currentThread().getPriority() + Thread.MAX_PRIORITY) / 2;
        } else {
            mPublishingQueuePriority = Thread.currentThread().getPriority();
        }
    }

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
     * Gets list of listeners.
     *
     * @return enumeration of listeners
     */
    public Enumeration getListeners() {
        return mListeners.elements();
    }

    /**
     * Gets request from publishing queue.
     *
     * @return request
     */
    public IRequest getRequest() {
       IRequest r = null;

        CMS.debug("getRequest 1  mRequests.size = " + mRequests.size());
        if (mRequests.size() > 0) {
            r = (IRequest)mRequests.elementAt(0);
            if (r != null) mRequests.remove(0);
        }
        CMS.debug("getRequest 2  mRequests.size = " + mRequests.size());

        return r;
    }

    /**
     * Gets number of requests in publishing queue.
     *
     * @return number of requests in publishing queue
     */
    public int getNumberOfRequests() {
        return mRequests.size();
    }

    /**
     * Checks if publishing queue is enabled.
     *
     * @return true if publishing queue is enabled, false otherwise
     */
    public boolean isPublishingQueueEnabled() {
        return mIsPublishingQueueEnabled;
    }

    /**
     * Sets maximum number of publishing threads.
     *
     * @param maxNumberOfThreads integer
     */
    public void setMaxNumberOfPublishingThreads(int maxNumberOfThreads) {
        if (maxNumberOfThreads > 1) {
            mMaxThreads = maxNumberOfThreads;
        }
        CMS.debug("Number of publishing threads set to " + mMaxThreads);
    }

    /**
     * Removes a notifier thread from the pool of publishing queue threads.
     *
     * @param notifierThread Thread
     */
    public synchronized void removeNotifierThread(Thread notifierThread) {
        CMS.debug("about removeNotifierThread "+ mNotifierThreads.size());
        if (mNotifierThreads.size() > 0) {
            mNotifierThreads.remove(notifierThread);
        }
        CMS.debug("removeNotifierThread done "+ mNotifierThreads.size());
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

    /**
     * Notifies all registered listeners about request.
     *
     * @param r request
     */
    public synchronized void addToNotify(IRequest r) {
        mRequests.addElement(r);
        CMS.debug("addToNotify  PublishingQueue: " + mRequests.size() + "  Threads: " + mNotifierThreads.size() + ":" + mMaxThreads +
                  " (" + Thread.currentThread().getPriority() + ", " + mPublishingQueuePriority + ", " + Thread.MAX_PRIORITY + ")");
        if (mNotifierThreads.size() < mMaxThreads) {
            try {
                Thread notifierThread = new Thread(new RunListeners((IRequestNotifier)this));
                if (notifierThread != null) {
                    mNotifierThreads.addElement(notifierThread);
                    if (mPublishingQueuePriority > 0) {
                        notifierThread.setPriority(mPublishingQueuePriority);
                    }
                    notifierThread.start();
                }
            } catch (Throwable e) {
                CMS.debug("addToNotify  exception: " + e.toString());
            }
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
    IRequestNotifier mRequestNotifier = null;

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
     * RunListeners class constructor.
     *
     * @param r request
     * @param listeners list of listeners
     */
    public RunListeners(IRequestNotifier requestNotifier) {
        mRequestNotifier = requestNotifier;
        mListeners = mRequestNotifier.getListeners();
    }

    /**
     * RunListeners thread implementation.
     */
    public void run() {
        CMS.debug("RunListeners::"+((mRequestNotifier != null && mRequestNotifier.getNumberOfRequests() > 0)?" Queue: "+mRequestNotifier.getNumberOfRequests():" noQueue")+
                  " "+((mRequest != null)?" SingleRequest":" noSingleRequest"));
        do {
            if (mRequestNotifier != null) mRequest = (IRequest)mRequestNotifier.getRequest();
            if (mListeners != null && mRequest != null) {
                while (mListeners.hasMoreElements()) {
                    IRequestListener l = (IRequestListener) mListeners.nextElement();
                    CMS.debug("RunListeners: IRequestListener = " + l.getClass().getName());
                    l.accept(mRequest);
                }
            }
            CMS.debug("RunListeners: "+((mRequestNotifier != null && mRequestNotifier.getNumberOfRequests() > 0)?" Queue: "+mRequestNotifier.getNumberOfRequests():" noQueue")+
                      " "+((mRequest != null)?" SingleRequest":" noSingleRequest"));
            if (mRequestNotifier != null) mListeners = mRequestNotifier.getListeners();
        } while (mRequestNotifier != null && mRequestNotifier.getNumberOfRequests() > 0);

        if (mRequestNotifier != null) mRequestNotifier.removeNotifierThread(Thread.currentThread());
    }
}
