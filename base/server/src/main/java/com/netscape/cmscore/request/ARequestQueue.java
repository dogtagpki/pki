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

import java.util.Date;
import java.util.Enumeration;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.request.INotify;
import com.netscape.certsrv.request.IPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestList;
import com.netscape.certsrv.request.IRequestScheduler;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;

/**
 * This class represents the request queue within the
 * certificate server. This class implements the state
 * engine for processing request objects.
 * <p>
 * There are several queues, such as KRA and CA requests.
 * Each of these request queues has a defined
 * set of policies, a notification service (for request
 * completion) and a service routine. The request queue
 * provides an interface for creating and viewing requests,
 * as well as performing operations on them.
 * <p>
 * !Put state machine description here!
 * <p>
 * This class defines several abstract protected functions
 * that need to be defined by the concrete implementation.
 * In particular, this class does not implement the operations
 * for storing requests persistently.
 * <p>
 * This class also provides several accessor functions for
 * setting fields in the request object. These functions are
 * provided for saving and restoring the state in the database.
 * <p>
 * This class also implements the locking operations.
 * <p>
 *
 * @author thayes
 * @version $Revision$ $Date$
 */
public abstract class ARequestQueue {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ARequestQueue.class);

    /**
     * global request version for tracking request changes.
     */
    public final static String REQUEST_VERSION = "1.0.0";

    // RequestIDTable mTable = new RequestIDTable();

    IPolicy mPolicy;
    IService mService;
    INotify mNotify;
    INotify mPendingNotify;

    IRequestScheduler mRequestScheduler;

    // Constructor
    protected ARequestQueue(IPolicy policy, IService service, INotify notify,
            INotify pendingNotify) {
        mPolicy = policy;
        mService = service;
        mNotify = notify;
        mPendingNotify = pendingNotify;
    }

    /**
     * Get complete list of RequestId values found i this
     * queue.
     * <p>
     * This method can form the basis for creating other types of search/list operations (although there are probably
     * more efficient ways of doing this. ARequestQueue implements default versions of some of the searching by using
     * this method as a basis.
     * <p>
     * TODO: return IRequestList -or- just use listRequests as the basic engine.
     * <p>
     *
     * @return
     *         an Enumeration that generates RequestId objects.
     */
    abstract protected Enumeration<RequestId> getRawList();

    /**
     * protected access for setting the modification time of a request.
     * <p>
     *
     * @param request
     *            The request to be modified.
     * @param date
     *            The new value for the time.
     */
    protected final void setModificationTime(IRequest request, Date date) {
        Request r = (Request) request;

        r.mModificationTime = date;
    }

    /**
     * protected access for setting the creation time of a request.
     * <p>
     *
     * @param request
     *            The request to be modified.
     * @param date
     *            The new value for the time.
     */
    protected final void setCreationTime(IRequest request, Date date) {
        Request r = (Request) request;

        r.mCreationTime = date;
    }

    /**
     * Clones a request object. A new request id is assigned
     * and all attributes of the request is copied to cloned request,
     * except for the sourceID of the original request
     * (remote authority's request Id).
     * <p>
     * The cloned request that is returned is LOCKED. The caller MUST release the request object by calling
     * releaseRequest().
     *
     * @param r request to be cloned
     * @return cloned request
     * @exception EBaseException failed to clone request
     */
    public abstract IRequest cloneRequest(IRequest r) throws EBaseException;

    /**
     * Sets request scheduler.
     *
     * @param scheduler request scheduler
     */
    public void setRequestScheduler(IRequestScheduler scheduler) {
        mRequestScheduler = scheduler;
    }

    /**
     * Gets request scheduler.
     *
     * @return request scheduler
     */
    public IRequestScheduler getRequestScheduler() {
        return mRequestScheduler;
    }

    /**
     * Begins processing for this request. This call
     * is valid only on requests with status BEGIN
     * An error is generated for other cases.
     *
     * @param r request to be processed
     * @exception EBaseException failed to process request
     */
    public final void processRequest(IRequest r)
            throws EBaseException {

        // #610553 Thread Scheduler
        IRequestScheduler scheduler = getRequestScheduler();

        if (scheduler != null) {
            scheduler.requestIn(r);
        }

        try {
            // 1. Check for valid state
            RequestStatus rs = r.getRequestStatus();

            if (rs != RequestStatus.BEGIN)
                throw new EBaseException("Invalid Status");

            stateEngine(r);
        } finally {
            if (scheduler != null) {
                scheduler.requestOut(r);
            }
        }
    }

    /**
     * Puts a new request into the PENDING state. This call is
     * only valid for requests with status BEGIN. An error is
     * generated for other cases.
     * <p>
     * This call might be used by agent servlets that want to copy a previous request, and resubmit it. By putting it
     * into PENDING state, the normal agent screens can be used for further processing.
     *
     * @param request
     *            the request to mark PENDING
     * @exception EBaseException failed to mark request as pending
     */
    public abstract void markRequestPending(IRequest request) throws EBaseException;

    /**
     * Clones a request object and mark it pending. A new request id is assigned
     * and all attributes of the request is copied to cloned request,
     * except for the sourceID of the original request
     * (remote authority's request Id).
     * <p>
     * The cloned request that is returned is LOCKED. The caller MUST release the request object by calling
     * releaseRequest().
     *
     * @param r request to be cloned
     * @return cloned request mark PENDING
     * @exception EBaseException failed to clone or mark request
     */
    public IRequest cloneAndMarkPending(IRequest r)
            throws EBaseException {
        IRequest clone = cloneRequest(r);

        markRequestPending(clone);
        return clone;
    }

    /**
     * Approves a request. The request must be locked.
     * <p>
     * This call will fail if: the request is not in PENDING state the policy modules do not accept the request
     * <p>
     * If the policy modules reject the request, then the request will remain in the PENDING state. Messages from the
     * policy module can be display to the agent to indicate the source of the problem.
     * <p>
     * The request processing code adds an AgentApproval to this request that contains the authentication id of the
     * agent. This data is retrieved from the Session object (qv).
     *
     * @param request
     *            the request that is being approved
     * @exception EBaseException failed to approve request
     */
    public abstract void approveRequest(IRequest request) throws EBaseException;

    /**
     * Rejects a request. The request must be locked.
     * <p>
     * This call will fail if: the request is not in PENDING state
     * <p>
     * The agent servlet (or other application) may wish to store AgentMessage values to indicate the reason for the
     * action
     *
     * @param request
     *            the request that is being rejected
     * @exception EBaseException failed to reject request
     */
    public abstract void rejectRequest(IRequest request) throws EBaseException;

    /**
     * Cancels a request. The request must be locked.
     * <p>
     * This call will fail if: the request is not in PENDING state
     * <p>
     * The agent servlet (or other application) may wish to store AgentMessage values to indicate the reason for the
     * action
     *
     * @param request
     *            the request that is being canceled
     * @exception EBaseException failed to cancel request
     */
    public abstract void cancelRequest(IRequest request) throws EBaseException;

    /**
     * Marks as serviced after destination authority has serviced request.
     * Used by connector.
     *
     * Caller must lock request and release request.
     *
     * @param request request
     */
    public abstract void markAsServiced(IRequest request) throws EBaseException;

    /**
     * Returns an enumerator that lists all RequestIds in the
     * queue. The caller should use the RequestIds to locate
     * each request by calling findRequest().
     * <p>
     * NOTE: This interface will not be useful for large databases. This needs to be replace by a VLV (paged) search
     * object.
     * <p>
     * Should be overridden by the specialized class if a more efficient method is available for implementing this
     * operation.
     *
     * @return request list
     */
    public IRequestList listRequests() {
        return new RequestList(getRawList());
    }

    /**
     * Returns an enumerator that lists all RequestIds for requests
     * that are in the given status. For example, all the PENDING
     * requests could be listed by specifying RequestStatus.PENDING
     * as the <i>status</i> argument
     * <p>
     * NOTE: This interface will not be useful for large databases. This needs to be replace by a VLV (paged) search
     * object.
     * <p>
     * Should be overridden by the specialized class if a more efficient method is available for implementing this
     * operation.
     *
     * @param s request status
     * @return request list
     */
    public abstract IRequestList listRequestsByStatus(RequestStatus s);

    /**
     * Gets requests that are pending on handling by the service
     * <p>
     *
     * @return list of pending requests
     */
    // public IRequestList listServicePendingRequests();

    /**
     * Locates a request from the SourceId.
     *
     * @param id
     *            a unique identifier for the record that is based on the source
     *            of the request, and possibly an identify assigned by the source.
     * @return
     *         The requestid corresponding to this source id. null is
     *         returned if the source id does not exist.
     */
    public abstract RequestId findRequestBySourceId(String id);

    /**
     * Locates all requests with a particular SourceId.
     * <p>
     *
     * @param id
     *            an identifier for the record that is based on the source
     *            of the request
     * @return
     *         A list of requests corresponding to this source id. null is
     *         returned if the source id does not exist.
     */
    public abstract IRequestList findRequestsBySourceId(String id);

    /**
     * Releases the LOCK on a request obtained from findRequest() or
     * newRequest()
     * <p>
     *
     * @param request request
     */
    public final void releaseRequest(IRequest request) {
        // mTable.unlock(request.getRequestId());
    }

    /**
     * Updates the request in the permanent data store.
     * <p>
     * This call can be made after changing a value like source id or owner, to force the new value to be written.
     * <p>
     * The request must be locked to make this call.
     *
     * @param r the request that is being updated
     * @exception EBaseException failed to update request
     */
    public abstract void updateRequest(IRequest r) throws EBaseException;

    // PRIVATE functions

    protected final void stateEngine(IRequest r)
            throws EBaseException {
        boolean complete = false;

        while (!complete) {
            RequestStatus rs = r.getRequestStatus();

            if (rs == RequestStatus.BEGIN) {
                PolicyResult pr = PolicyResult.ACCEPTED;

                if (mPolicy != null)
                    pr = mPolicy.apply(r);

                if (pr == PolicyResult.ACCEPTED) {
                    r.setRequestStatus(RequestStatus.APPROVED);
                } else if (pr == PolicyResult.DEFERRED) {
                    r.setRequestStatus(RequestStatus.PENDING);
                } else {
                    r.setRequestStatus(RequestStatus.REJECTED);
                }

                // if policy accepts the request, the request
                // will be processed right away. So speed up
                // the request processing, we do not want to
                // have too many db operation.
                if (pr != PolicyResult.ACCEPTED) {
                    updateRequest(r);
                }
            } else if (rs == RequestStatus.PENDING) {
                if (mPendingNotify != null)
                    mPendingNotify.notify(r);

                complete = true;
            } else if (rs == RequestStatus.APPROVED) {
                boolean svcComplete;

                svcComplete = mService.serviceRequest(r);

                // Completed requests call the notifier and are done. Others
                // wait for the serviceComplete call.
                if (svcComplete) {
                    r.setRequestStatus(RequestStatus.COMPLETE);
                } else {
                    r.setRequestStatus(RequestStatus.SVC_PENDING);
                }

                updateRequest(r);
            } else if (rs == RequestStatus.SVC_PENDING) {
                complete = true;
            } else if (rs == RequestStatus.CANCELED) {
                if (mNotify != null)
                    mNotify.notify(r);

                complete = true;
            } else if (rs == RequestStatus.REJECTED) {
                if (mNotify != null)
                    mNotify.notify(r);

                complete = true;
            } else if (rs == RequestStatus.COMPLETE) {
                if (mNotify != null)
                    mNotify.notify(r);

                complete = true;
            }
        }
    }

    /**
     * log a change in the request status
     */
    protected void logChange(IRequest request) {
        // write the queue name and request id
        // write who changed it
        // write what change (which state change) was made
        //   - new (processRequest)
        //   - approve
        //   - reject

        // Ordering
        //  - make change in memory
        //  - log change and result
        //  - update record
    }

    /**
     * get the identity of the current user
     */
    protected String getUserIdentity() {
        // Record agent who did this
        SessionContext s = SessionContext.getContext();
        String name = (String) s.get(SessionContext.USER_ID);

        return name;
    }

    /**
     * Resends requests
     *
     * New non-blocking recover method.
     */
    public void recover() {
        CMSEngine engine = CMS.getCMSEngine();
        if (engine.isRunningMode()) {
            RecoverThread t = new RecoverThread(this);

            t.start();
        }
    }

    /**
     * recover from a crash. Resends all requests that are in
     * the APPROVED state.
     */
    public abstract void recoverWillBlock();

    /**
     * Retrieves the notifier for pending request.
     *
     * @return notifier for pending request
     */
    public INotify getPendingNotify() {
        return mPendingNotify;
    }
}

//
// Table of RequestId values that are currently in use by some thread.
// The fact that the request is in this table constitutes a lock
// on the value.
//
/*
 class RequestIDTable {
 public synchronized void lock(RequestId id) {
 while (true) {
 if (mHashtable.put(id, id) == null)
 break;

 try {
 wait();
 } catch (InterruptedException e) {
 };
 }
 }

 public synchronized void unlock(RequestId id) {
 mHashtable.remove(id);

 notifyAll();
 }

 // instance variables
 Hashtable mHashtable = new Hashtable();
 }
 */
