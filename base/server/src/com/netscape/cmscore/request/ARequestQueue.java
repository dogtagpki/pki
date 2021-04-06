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
import java.util.Date;
import java.util.Enumeration;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.request.AgentApprovals;
import com.netscape.certsrv.request.INotify;
import com.netscape.certsrv.request.IPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestList;
import com.netscape.certsrv.request.IRequestScheduler;
import com.netscape.certsrv.request.IRequestVirtualList;
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
     * Create a new (unique) RequestId. (abstract)
     * <p>
     * This method must be implemented by the specialized class to generate a new id from data in the persistant store.
     * This id is used to create a new request object.
     * <p>
     *
     * @return
     *         a new RequestId object.
     * @exception EBaseException
     *                indicates that creation of the new id could not be completed.
     * @see RequestId
     */
    public abstract RequestId newRequestId()
            throws EBaseException;

    /**
     * Create a new synchronous request ID
     */
    public abstract RequestId newEphemeralRequestId();

    /**
     * Read a request from the persistant store. (abstract)
     * <p>
     * This function is called to create the in-memory version of a request object.
     * <p>
     * The implementation of this object can use the createRequest member function to create a new instance of an
     * IRequest, and use the setRequestStatus, setCreationTime and setModificationTime functions to set those values.
     * <p>
     *
     * @param id
     *            the id of the request to read.
     * @return
     *         a new IRequest object. null is returned if the object cannot
     *         be located.
     * @exception EBaseException
     *                TODO: this is not implemented yet
     * @see #createRequest
     * @see #setRequestStatus
     * @see #setModificationTime
     * @see #setCreationTime
     */
    protected abstract IRequest readRequest(RequestId id);

    /**
     * Add the request to the store. (abstract)
     * <p>
     * This function is called when a new request immediately after creating a new request.
     * <p>
     *
     * @param request
     *            the request to add.
     * @exception EBaseException
     *                TODO: this is not implemented yet
     */
    protected abstract void addRequest(IRequest request) throws EBaseException;

    /**
     * Modify the request in the store. (abstract)
     * <p>
     * Update the persistant copy of this request with the current values in the object.
     * <p>
     * Currently there are no hints for what has changed, so the entire request should be updated.
     * <p>
     *
     * @param request
     * @exception EBaseException
     *                TODO: this is not implemented yet
     */
    protected abstract void modifyRequest(IRequest request);

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
     * protected access for setting the current state of a request.
     * <p>
     *
     * @param request
     *            The request to be modified.
     * @param status
     *            The new value for the request status.
     */
    protected final void setRequestStatus(IRequest request, RequestStatus status) {
        Request r = (Request) request;

        r.setRequestStatus(status);
    }

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
     * protected access for creating a new Request object
     * <p>
     *
     * @param id
     *            The identifier for the new request
     * @return
     *         A new request object. The caller should fill in other data
     *         values from the datastore.
     */
    protected final IRequest createRequest(RequestId id, String requestType) {
        Request r;

        /*
         * Determine the specialized class to create for this type
         *
         * TODO: this set of classes is an example only.  The real set
         *   needs to be determined and implemented.
         */
        if (requestType != null && requestType.equals("enrollment")) {
            r = new EnrollmentRequest(id);
        } else {
            r = new Request(id);
        }

        return r;
    }

    /**
     * Creates a new request object. A request id is
     * assigned to it - see IRequest.getRequestId, and
     * the status is set to RequestStatus.BEGIN
     * <p>
     * The request is LOCKED. The caller MUST release the request object by calling releaseRequest().
     * <p>
     * TODO: provide other required values (such as type and sourceId)
     *
     * @param requestType request type
     * @return new request
     * @exception EBaseException failed to create new request
     */
    public IRequest newRequest(String requestType) throws EBaseException {
        RequestId requestID = newRequestId();
        return newRequest(requestID, requestType);
    }

    /**
     * Create a new Request object and assign a request ID.
     * See newRequest() for details.
     *
     * @param requestID - request ID
     * @param requestType - request type
     * @return new request
     * @exception EBaseException failed to create new request
     */
    public IRequest newRequest(RequestId requestID, String requestType) throws EBaseException {

        if (requestType == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_REQUEST_TYPE", "null"));
        }

        IRequest r = createRequest(requestID, requestType);

        // Commented out the lock call because unlock is never called.
        // mTable.lock(rId);

        // TODO: move this to the first update. This will require
        // some state information to track the current state.
        r.setRequestType(requestType);
        r.setExtData(IRequest.REQ_VERSION, REQUEST_VERSION);

        // NOT_UPDATED mean request is in memory and has
        // not been serialized to database yet. An add
        // operation is required to serialize a NOT_UPDATED
        // request.
        r.setExtData("dbStatus", "NOT_UPDATED");
        // addRequest(r);

        // expose requestId to policy so that it can be
        // used with predicate
        r.setExtData("requestId", requestID.toString());

        return r;
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
    public IRequest cloneRequest(IRequest r)
            throws EBaseException {
        // 1. check for valid state. (Are any invalid ?)
        RequestStatus rs = r.getRequestStatus();

        if (rs == RequestStatus.BEGIN)
            throw new EBaseException("Invalid Status");

        // 2. create new request
        String reqType = r.getRequestType();
        IRequest clone = newRequest(reqType);

        // 3. copy all attributes of original request to clone and modify.
        // source id (from remote authority) is not copied.
        // TODO: set the original request id to some place in the request.
        clone.copyContents(r);
        // NOT_UPDATED mean request is in memory and has
        // not been serialized to database yet. An add
        // operation is required to serialize a NOT_UPDATED
        // request.
        clone.setExtData("dbStatus", "NOT_UPDATED");

        return clone;
    }

    /**
     * Gets the Request corresponding to id.
     * Returns null if the id does not correspond
     * to a valid request id.
     * <p>
     * Errors may be generated for other conditions.
     *
     * @param id request id
     * @return found request
     * @exception EBaseException failed to access request queue
     */
    public IRequest findRequest(RequestId id)
            throws EBaseException {
        IRequest r;

        // mTable.lock(id);

        r = readRequest(id);

        // if (r == null) mTable.unlock(id);

        return r;
    }

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
     * @param req request to be processed
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
     * @param req
     *            the request to mark PENDING
     * @exception EBaseException failed to mark request as pending
     */
    public final void markRequestPending(IRequest r)
            throws EBaseException {
        // 1. Check for valid state
        RequestStatus rs = r.getRequestStatus();

        if (rs != RequestStatus.BEGIN)
            throw new EBaseException("Invalid Status");

        // 2. Change the request state.  This method of making
        // a request PENDING does NOT invoke the PENDING notifiers.
        // To change this, just call stateEngine at the completion of this
        // routine.
        setRequestStatus(r, RequestStatus.PENDING);

        updateRequest(r);
        stateEngine(r);
    }

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
    public final void approveRequest(IRequest r)
            throws EBaseException {
        // 1. Check for valid state
        RequestStatus rs = r.getRequestStatus();

        if (rs != RequestStatus.PENDING)
            throw new EBaseException("Invalid Status");

        AgentApprovals aas = AgentApprovals.fromStringVector(
                r.getExtDataInStringVector(AgentApprovals.class.getName()));
        if (aas == null) {
            aas = new AgentApprovals();
        }

        // Record agent who did this
        String agentName = getUserIdentity();

        if (agentName == null)
            throw new EBaseException("Missing agent information");

        aas.addApproval(agentName);
        r.setExtData(AgentApprovals.class.getName(), aas.toStringVector());

        PolicyResult pr = mPolicy.apply(r);

        if (pr == PolicyResult.ACCEPTED) {
            setRequestStatus(r, RequestStatus.APPROVED);
        } else if (pr == PolicyResult.DEFERRED ||
                pr == PolicyResult.REJECTED) {
        }

        // Always update. The policy code may have made changes to the
        // request that we want to keep.
        updateRequest(r);

        stateEngine(r);
    }

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
    public final void rejectRequest(IRequest r)
            throws EBaseException {
        // 1. Check for valid state
        RequestStatus rs = r.getRequestStatus();

        if (rs != RequestStatus.PENDING)
            throw new EBaseException("Invalid Status");

        // 2. Change state
        setRequestStatus(r, RequestStatus.REJECTED);
        updateRequest(r);

        // 3. Continue processing
        stateEngine(r); // does nothing
    }

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
    public final void cancelRequest(IRequest r)
            throws EBaseException {
        setRequestStatus(r, RequestStatus.CANCELED);
        updateRequest(r);

        stateEngine(r);

        return;
    }

    /**
     * Marks as serviced after destination authority has serviced request.
     * Used by connector.
     *
     * Caller must lock request and release request.
     *
     * @param r request
     */
    public final void markAsServiced(IRequest r) {
        setRequestStatus(r, RequestStatus.COMPLETE);
        try {
            updateRequest(r);
        } catch (EBaseException e) {
            throw new RuntimeException(e);
        }

        if (mNotify != null)
            mNotify.notify(r);

        return;
    }

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
     * @param status request status
     * @return request list
     */
    public IRequestList listRequestsByStatus(RequestStatus s) {
        return new RequestListByStatus(getRawList(), s, this);
    }

    public abstract IRequestList listRequestsByFilter(String filter);

    /**
     * Returns an enumerator that lists all RequestIds for requests
     * that match the filter.
     * <p>
     * NOTE: This interface will not be useful for large databases. This needs to be replace by a VLV (paged) search
     * object.
     *
     * @param filter search filter
     * @param maxSize max size to return
     * @return request list
     */
    public abstract IRequestList listRequestsByFilter(String filter, int maxSize);

    /**
     * Returns an enumerator that lists all RequestIds for requests
     * that match the filter.
     * <p>
     * NOTE: This interface will not be useful for large databases. This needs to be replace by a VLV (paged) search
     * object.
     *
     * @param filter search filter
     * @param maxSize max size to return
     * @param timeLimit timeout value for the search
     * @return request list
     */
    public abstract IRequestList listRequestsByFilter(String filter, int maxSize, int timeLimit);

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
     * @param r request
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
     * @param request
     *            the request that is being updated
     * @exception EBaseException failed to update request
     */
    public void updateRequest(IRequest r) throws EBaseException {
        // defualt is to really update ldap
        String delayLDAPCommit = r.getExtDataInString("delayLDAPCommit");
        ((Request) r).mModificationTime = new Date();

        String name = getUserIdentity();

        if (name != null)
            r.setExtData(IRequest.UPDATED_BY, name);

        // by default, write request to LDAP
        if (delayLDAPCommit == null || !delayLDAPCommit.equals("true")) {
            // TODO: use a state flag to determine whether to call
            // addRequest or modifyRequest (see newRequest as well)
            modifyRequest(r);
        } // else: delay the write to ldap
    }

    // PRIVATE functions

    private final void stateEngine(IRequest r)
            throws EBaseException {
        boolean complete = false;

        while (!complete) {
            RequestStatus rs = r.getRequestStatus();

            if (rs == RequestStatus.BEGIN) {
                PolicyResult pr = PolicyResult.ACCEPTED;

                if (mPolicy != null)
                    pr = mPolicy.apply(r);

                if (pr == PolicyResult.ACCEPTED) {
                    setRequestStatus(r, RequestStatus.APPROVED);
                } else if (pr == PolicyResult.DEFERRED) {
                    setRequestStatus(r, RequestStatus.PENDING);
                } else {
                    setRequestStatus(r, RequestStatus.REJECTED);
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
                    setRequestStatus(r, RequestStatus.COMPLETE);
                } else {
                    setRequestStatus(r, RequestStatus.SVC_PENDING);
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
     * Gets a pageable list of IRequest entries in this queue.
     *
     * @param pageSize page size
     * @return request list
     */
    public abstract IRequestVirtualList getPagedRequests(int pageSize);

    /**
     * Gets a pageable list of IRequest entries in this queue.
     *
     * @param filter search filter
     * @param pageSize page size
     * @param sortKey the attributes to sort by
     * @return request list
     */
    public abstract IRequestVirtualList getPagedRequestsByFilter(String filter,
                                                        int pageSize,
                                                        String sortKey);

    /**
     * Gets a pageable list of IRequest entries in this queue.
     *
     * @param fromId request id to start with
     * @param filter search filter
     * @param pageSize page size
     * @param sortKey the attributes to sort by
     * @return request list
     */
    public abstract IRequestVirtualList getPagedRequestsByFilter(RequestId fromId,
                                                        String filter,
                                                        int pageSize,
                                                        String sortKey);

    /**
     * Gets a pageable list of IRequest entries in this queue. This
     * jumps right to the end of the list
     *
     * @param fromId request id to start with
     * @param jumpToEnd jump to end of list (set fromId to null)
     * @param filter search filter
     * @param pageSize page size
     * @param sortKey the attributes to sort by
     * @return request list
     */
    public abstract IRequestVirtualList getPagedRequestsByFilter(RequestId fromId,
                                   boolean jumpToEnd, String filter,
                                   int pageSize,
                                   String sortKey);


    /**
     * recover from a crash. Resends all requests that are in
     * the APPROVED state.
     */
    public void recoverWillBlock() {
        // Get a list of all requests that are APPROVED
        IRequestList list = listRequestsByStatus(RequestStatus.APPROVED);

        while (list != null && list.hasMoreElements()) {
            RequestId rid = list.nextRequestId();
            IRequest request;

            try {
                request = findRequest(rid);

                //if (request == null) log_error

                // Recheck the status - should be the same!!
                if (request.getRequestStatus() == RequestStatus.APPROVED) {
                    stateEngine(request);
                }

                releaseRequest(request);
            } catch (EBaseException e) {
                // log
            }
        }
    }

    /**
     * Retrieves the notifier for pending request.
     *
     * @return notifier for pending request
     */
    public INotify getPendingNotify() {
        return mPendingNotify;
    }

    public abstract BigInteger getLastRequestIdInRange(BigInteger reqId_low_bound, BigInteger reqId_upper_bound);
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
