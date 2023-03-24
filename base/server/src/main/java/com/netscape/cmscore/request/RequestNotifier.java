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

import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.request.IRequestVirtualList;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestListener;
import com.netscape.cmscore.apps.CMSEngine;

/**
 * The RequestNotifier can be registered with a RequestQueue,
 * so it will be invoked when a request is completely serviced
 * by the IService object, then it will notify all registered
 * request listeners.
 */
public class RequestNotifier {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RequestNotifier.class);

    protected CMSEngine engine;

    private Hashtable<String, RequestListener> mListeners = new Hashtable<>();
    private Vector<Thread> mNotifierThreads = new Vector<>();
    private Vector<String> mRequests = new Vector<>();
    private int mMaxRequests = 100;
    private boolean mSearchForRequests = false;
    private int mMaxThreads = 1;

    private boolean mIsPublishingQueueEnabled = false;
    private int mPublishingQueuePriority = 0;

    private String mPublishingStatus = null;
    private int mSavePublishingStatus = 0;
    private int mSavePublishingCounter = 0;

    public RequestNotifier() {
        mPublishingQueuePriority = Thread.currentThread().getPriority();
    }

    public CMSEngine getCMSEngine() {
        return engine;
    }

    public void setCMSEngine(CMSEngine engine) {
        this.engine = engine;
    }

    /**
     * Sets publishing queue parameters.
     *
     * @param isPublishingQueueEnabled publishing queue switch
     * @param publishingQueuePriorityLevel publishing queue priority level
     * @param maxNumberOfPublishingThreads maximum number of publishing threads
     * @param publishingQueuePageSize publishing queue page size
     */
    public void setPublishingQueue(boolean isPublishingQueueEnabled,
                                    int publishingQueuePriorityLevel,
                                    int maxNumberOfPublishingThreads,
                                    int publishingQueuePageSize,
                                    int savePublishingStatus) {
        logger.debug("setPublishingQueue:  Publishing Queue Enabled: " + isPublishingQueueEnabled +
                  "  Priority Level: " + publishingQueuePriorityLevel +
                  "  Maximum Number of Threads: " + maxNumberOfPublishingThreads +
                  "  Page Size: " + publishingQueuePageSize);
        mIsPublishingQueueEnabled = isPublishingQueueEnabled;
        mMaxThreads = maxNumberOfPublishingThreads;
        mMaxRequests = publishingQueuePageSize;
        mSavePublishingStatus = savePublishingStatus;

        // Publishing Queue Priority Levels:  2 - maximum, 1 - higher, 0 - normal, -1 - lower, -2 - minimum
        if (publishingQueuePriorityLevel > 1) {
            mPublishingQueuePriority = Thread.MAX_PRIORITY;
        } else if (publishingQueuePriorityLevel > 0) {
            mPublishingQueuePriority = (Thread.currentThread().getPriority() + Thread.MAX_PRIORITY) / 2;
        } else if (publishingQueuePriorityLevel < -1) {
            mPublishingQueuePriority = Thread.MIN_PRIORITY;
        } else if (publishingQueuePriorityLevel < 0) {
            mPublishingQueuePriority = (Thread.currentThread().getPriority() + Thread.MIN_PRIORITY) / 2;
        } else {
            mPublishingQueuePriority = Thread.currentThread().getPriority();
        }

        RequestRepository requestRepository = engine.getRequestRepository();

        if (mIsPublishingQueueEnabled && mSavePublishingStatus > 0 && requestRepository != null) {
            mPublishingStatus = requestRepository.getPublishingStatus();
            try {
                BigInteger status = new BigInteger(mPublishingStatus);
                if (status.compareTo(BigInteger.ZERO) > -1) {
                    recoverPublishingQueue(mPublishingStatus);
                }
            } catch (Exception e) {
                logger.warn("setPublishingQueue:  Exception: " + e.getMessage(), e);
            }
        }

    }

    /**
     * Registers a request listener.
     *
     * @param listener listener to be registered
     */
    public void registerListener(RequestListener listener) {
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
    public void registerListener(String name, RequestListener listener) {
        mListeners.put(name, listener);
    }

    /**
     * Removes listener from the list of registered listeners.
     *
     * @param listener listener to be removed from the list
     */
    public void removeListener(RequestListener listener) {
        // XXX should check for duplicates here or allow listeners
        // to register twice and call twice ?
        mListeners.remove(listener.getClass().getName());
    }

    /**
     * Gets list of listener names.
     *
     * @return enumeration of listener names
     */
    public Enumeration<String> getListenerNames() {
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
    public RequestListener getListener(String name) {
        return mListeners.get(name);
    }

    /**
     * Gets list of listeners.
     *
     * @return enumeration of listeners
     */
    public Enumeration<RequestListener> getListeners() {
        return mListeners.elements();
    }

    private Object publishingCounterMonitor = new Object();

    public void updatePublishingStatus(String id) {

        RequestRepository requestRepository = engine.getRequestRepository();

        if (requestRepository != null) {
            synchronized (publishingCounterMonitor) {
                if (mSavePublishingCounter == 0) {
                    logger.debug("updatePublishingStatus  requestId: " + id);
                    requestRepository.setPublishingStatus(id);
                }
                mSavePublishingCounter++;
                logger.debug("updatePublishingStatus  mSavePublishingCounter: " + mSavePublishingCounter +
                          " mSavePublishingStatus: " + mSavePublishingStatus);
                if (mSavePublishingCounter >= mSavePublishingStatus) {
                    mSavePublishingCounter = 0;
                }
            }
        } else {
            logger.warn("updatePublishingStatus  requestQueue == null");
        }
    }

    /**
     * Gets request from publishing queue.
     *
     * @return request
     */
    public synchronized Request getRequest() {
        Request r = null;
        String id = null;

        logger.debug("getRequest  mRequests=" + mRequests.size() + "  mSearchForRequests=" + mSearchForRequests);
        if (mSearchForRequests && mRequests.size() == 1) {

            id = mRequests.elementAt(0);
            RequestRepository requestRepository = engine.getRequestRepository();

            if (id != null && requestRepository != null) {
                logger.debug("getRequest  request id=" + id);

                IRequestVirtualList list;
                try {
                    list = requestRepository.getPagedRequestsByFilter(
                            new RequestId(id),
                            false,
                            "(requeststate=complete)",
                            mMaxRequests,
                            "requestId");

                } catch (EBaseException e) {
                    throw new RuntimeException(e);
                }

                int s = list.getSize() - list.getCurrentIndex();
                logger.debug("getRequest  list size: " + s);
                for (int i = 0; i < s; i++) {
                    r = null;
                    try {
                        r = list.getElementAt(i);
                    } catch (Exception e) {
                        // handled below
                    }
                    if (r == null) {
                        continue;
                    }
                    String requestType = r.getRequestType();
                    if (requestType == null) {
                        continue;
                    }
                    if (!(requestType.equals(Request.ENROLLMENT_REQUEST) ||
                            requestType.equals(Request.RENEWAL_REQUEST) ||
                            requestType.equals(Request.REVOCATION_REQUEST) ||
                            requestType.equals(Request.CMCREVOKE_REQUEST) ||
                            requestType.equals(Request.UNREVOCATION_REQUEST))) {
                        continue;
                    }
                    if (i == 0 && id.equals(r.getRequestId().toString())) {
                        if (s == 1) {
                            break;
                        }
                        continue;
                    }
                    if (mRequests.size() < mMaxRequests) {
                        mRequests.addElement(r.getRequestId().toString());
                        logger.debug("getRequest  added "
                                + r.getRequestType() + " request " + r.getRequestId().toString() +
                                  " to mRequests: " + mRequests.size() + " (" + mMaxRequests + ")");
                    } else {
                        break;
                    }
                }
                logger.debug("getRequest  done with adding requests to mRequests: " + mRequests.size());
            } else {
                logger.warn("getRequest  has no access to the request queue");
            }
        }
        if (mRequests.size() > 0) {
            id = mRequests.elementAt(0);
            if (id != null) {
                logger.debug("getRequest  getting request: " + id);
                RequestRepository requestRepository = engine.getRequestRepository();

                if (requestRepository != null) {
                    try {
                        r = requestRepository.readRequest(new RequestId(id));
                        mRequests.remove(0);
                        logger.debug("getRequest  request " + id + ((r != null) ? " found" : " not found"));
                        //updatePublishingStatus(id);
                    } catch (EBaseException e) {
                        logger.warn("getRequest  Exception: " + e.getMessage(), e);
                    }
                } else {
                    logger.warn("getRequest  has no access to the request queue");
                }
            }
            if (mRequests.size() == 0) {
                mSearchForRequests = false;
            }
        }
        logger.debug("getRequest  mRequests=" + mRequests.size() + "  mSearchForRequests=" + mSearchForRequests + " done");

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
     * Removes a notifier thread from the pool of publishing queue threads.
     *
     * @param notifierThread Thread
     */
    public void removeNotifierThread(Thread notifierThread) {
        if (mNotifierThreads.size() > 0) {
            mNotifierThreads.remove(notifierThread);
            if (mNotifierThreads.size() == 0) {
                RequestRepository requestRepository = engine.getRequestRepository();
                if (requestRepository != null) {
                    requestRepository.setPublishingStatus("-1");
                }
            }
        }
        logger.debug("Number of publishing threads: " + mNotifierThreads.size());
    }

    /**
     * Provides notification that a request has been completed.
     * The implementation may use values stored in the Request
     * object, and may implement any type publishing (such as email
     * or writing values into a directory)
     *
     * @param r the request that is completed.
     */
    public void notify(Request r) {
        logger.info("RequestNotifier: Request " + r.getRequestId().toHexString() + " " + r.getRequestStatus());
        logger.info("RequestNotifier: - publishing queue enabled: " + mIsPublishingQueueEnabled);
        logger.info("RequestNotifier: - max threads: " + mMaxThreads);

        if (mIsPublishingQueueEnabled) {
            logger.info("RequestNotifier: Notifying " + mListeners.size() + " listener(s) through a queue");
            addToNotify(r);

        } else if (mMaxThreads == 0) {
            logger.info("RequestNotifier: Notifying " + mListeners.size() + " listener(s) synchronously");
            Enumeration<RequestListener> listeners = mListeners.elements();
            if (listeners != null && r != null) {
                while (listeners.hasMoreElements()) {
                    RequestListener l = listeners.nextElement();
                    logger.info("RequestNotifier: Processing request " + r.getRequestId().toHexString() + " with " + l.getClass().getSimpleName());
                    l.accept(r);
                }
            }

        } else {
            logger.info("RequestNotifier: Notifying " + mListeners.size() + " listener(s) asynchronously");
            try {
                new Thread(new RunListeners(r, mListeners.elements()), "RequestNotifier-notify").start();
            } catch (Throwable e) {
                logger.warn("Could not run listeners for request " + r.getRequestId().toHexString() + ": " + e.getMessage(), e);
            }
        }
    }

    /**
     * Checks for available publishing connections
     *
     * @return true if there are available publishing connections, false otherwise
     */
    public boolean checkAvailablePublishingConnections() {
        return false;
    }

    /**
     * Checks if more publishing threads can be added.
     *
     * @return true if more publishing threads can be added, false otherwise
     */
    private boolean morePublishingThreads() {
        boolean moreThreads = false;

        if (mNotifierThreads.size() == 0) {
            moreThreads = true;
        } else if (mNotifierThreads.size() < mMaxThreads) {
            logger.debug("morePublishingThreads  (" + mRequests.size() + ">" +
                      ((mMaxRequests * mNotifierThreads.size()) / mMaxThreads) +
                      " " + "(" + mMaxRequests + "*" + mNotifierThreads.size() + "):" + mMaxThreads);
            // gradually add new publishing threads
            if (mRequests.size() > ((mMaxRequests * mNotifierThreads.size()) / mMaxThreads)) {
                // check for available publishing connections
                if (checkAvailablePublishingConnections()) {
                    moreThreads = true;
                }
            }
        }
        logger.debug("morePublishingThreads  moreThreads: " + moreThreads);

        return moreThreads;
    }

    /**
     * Notifies all registered listeners about request.
     *
     * @param r request
     */
    public synchronized void addToNotify(Request r) {

        logger.info("RequestNotifier: Notifying all listeners for request " + r.getRequestId().toHexString());

        if (!mSearchForRequests) {

            logger.info("RequestNotifier: - max requests: " + mMaxRequests);
            logger.info("RequestNotifier: - buffer size: " + mRequests.size());

            if (mRequests.size() < mMaxRequests) {
                logger.info("RequestNotifier: Extending buffer");
                mRequests.addElement(r.getRequestId().toString());

                if (morePublishingThreads()) {
                    try {
                        Thread notifierThread = new Thread(new RunListeners(this), "RequestNotifier-addToNotify");
                        if (notifierThread != null) {
                            mNotifierThreads.addElement(notifierThread);
                            logger.info("RequestNotifier: - publishing threads: " + mNotifierThreads.size());
                            if (mPublishingQueuePriority > 0) {
                                notifierThread.setPriority(mPublishingQueuePriority);
                            }
                            notifierThread.start();
                        }

                    } catch (Throwable e) {
                        logger.warn("Unable to notify listeners: " + e.getMessage(), e);
                    }
                }

            } else {
                mSearchForRequests = true;
            }
        }
    }

    /**
     * Recovers publishing queue.
     *
     * @param id request request
     */
    public void recoverPublishingQueue(String id) {

        logger.info("RequestNotifier: Recovering publishing queue for request " + id);
        logger.info("RequestNotifier: - requests: " + mRequests.size());
        logger.info("RequestNotifier: - max requests: " + mMaxRequests);

        if (mRequests.size() == 0) {
            logger.info("RequestNotifier: Extending buffer");
            mRequests.addElement(id);

            if (morePublishingThreads()) {
                synchronized (this) {
                    mSearchForRequests = true;
                }

                try {
                    Thread notifierThread = new Thread(new RunListeners(this), "RequestNotifier-recoverPublishingQueue");
                    if (notifierThread != null) {
                        mNotifierThreads.addElement(notifierThread);
                        logger.info("RequestNotifier: - publishing threads: " + mNotifierThreads.size());
                        if (mPublishingQueuePriority > 0) {
                            notifierThread.setPriority(mPublishingQueuePriority);
                        }
                        notifierThread.start();
                    }

                } catch (Throwable e) {
                    logger.warn("Unable to recover publishing queue: " + e.getMessage(), e);
                }
            }
        }
    }
}
