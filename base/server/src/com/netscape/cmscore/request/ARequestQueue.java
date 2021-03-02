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
import com.netscape.certsrv.request.AgentApprovals;
import com.netscape.certsrv.request.INotify;
import com.netscape.certsrv.request.IPolicy;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestList;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.IRequestScheduler;
import com.netscape.certsrv.request.IService;
import com.netscape.certsrv.request.PolicyResult;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;

/**
 * The ARequestQueue class is an abstract class that implements
 * most portions of the IRequestQueue interface. This includes
 * the state engine as defined for processing IRequest objects.
 * <p>
 * !Put state machine description here!
 * <p>
 * This class defines several abstract protected functions that need to be defined by the concrete implementation. In
 * particular, this class does not implement the operations for storing requests persistantly.
 * <p>
 * This class also provides several accessor functions for setting fields in the IRequest object. These functions are
 * provided as an aid to saving and restoring the state in the database.
 * <p>
 * This class also implements the locking operations specified by the IRequestQueue interface.
 * <p>
 *
 * @author thayes
 * @version $Revision$ $Date$
 */
public abstract class ARequestQueue
        implements IRequestQueue {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ARequestQueue.class);

    /**
     * global request version for tracking request changes.
     */
    public final static String REQUEST_VERSION = "1.0.0";

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
    protected abstract RequestId newRequestId()
            throws EBaseException;

    /**
     * Create a new synchronous request ID
     */
    protected abstract RequestId newEphemeralRequestId();

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

    public IRequest newRequest(String requestType) throws EBaseException {
        return newRequest(requestType, false);
    }

    /**
     * Implements IRequestQueue.newRequest
     * <p>
     *
     * @see IRequestQueue#newRequest
     */
    public IRequest newRequest(String requestType, boolean ephemeral)
            throws EBaseException {
        if (requestType == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_REQUEST_TYPE", "null"));
        }

        RequestId rId = null;
        if(! ephemeral) {
            rId = newRequestId();
        } else {
            rId = newEphemeralRequestId();
        }

        IRequest r = createRequest(rId, requestType);

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
        r.setExtData("requestId", rId.toString());

        return r;
    }

    /**
     * Implements IRequestQueue.cloneRequest
     * <p>
     *
     * @see IRequestQueue#cloneRequest
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
     * Implements IRequestQueue.findRequest
     * <p>
     *
     * @see IRequestQueue#findRequest
     */
    public IRequest findRequest(RequestId id)
            throws EBaseException {
        IRequest r;

        // mTable.lock(id);

        r = readRequest(id);

        // if (r == null) mTable.unlock(id);

        return r;
    }

    private IRequestScheduler mRequestScheduler = null;

    public void setRequestScheduler(IRequestScheduler scheduler) {
        mRequestScheduler = scheduler;
    }

    public IRequestScheduler getRequestScheduler() {
        return mRequestScheduler;
    }

    /**
     * Implements IRequestQueue.processRequest
     * <p>
     *
     * @see IRequestQueue#processRequest
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
     * Implements IRequestQueue.markRequestPending
     * <p>
     *
     * @see IRequestQueue#markRequestPending
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
     * Implements IRequestQueue.cloneAndMarkPending
     * <p>
     *
     * @see IRequestQueue#cloneAndMarkPending
     */
    public IRequest cloneAndMarkPending(IRequest r)
            throws EBaseException {
        IRequest clone = cloneRequest(r);

        markRequestPending(clone);
        return clone;
    }

    /**
     * Implements IRequestQueue.approveRequest
     * <p>
     *
     * @see IRequestQueue#approveRequest
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
     * Implements IRequestQueue.rejectRequest
     * <p>
     *
     * @see IRequestQueue#rejectRequest
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
     * Implments IRequestQueue.cancelRequest
     * <p>
     *
     * @see IRequestQueue#cancelRequest
     */
    public final void cancelRequest(IRequest r)
            throws EBaseException {
        setRequestStatus(r, RequestStatus.CANCELED);
        updateRequest(r);

        stateEngine(r);

        return;
    }

    /**
     * caller must lock request and release request
     */
    public final void markAsServiced(IRequest r) {
        setRequestStatus(r, RequestStatus.COMPLETE);
        updateRequest(r);

        if (mNotify != null)
            mNotify.notify(r);

        return;
    }

    /**
     * Implements IRequestQueue.listRequests
     * <p>
     * Should be overridden by the specialized class if a more efficient method is available for implementing this
     * operation.
     * <P>
     *
     * @see IRequestQueue#listRequests
     */
    public IRequestList listRequests() {
        return new RequestList(getRawList());
    }

    /**
     * Implements IRequestQueue.listRequestsByStatus
     * <p>
     * Should be overridden by the specialized class if a more efficient method is available for implementing this
     * operation.
     * <P>
     *
     * @see IRequestQueue#listRequestsByStatus
     */
    public IRequestList listRequestsByStatus(RequestStatus s) {
        return new RequestListByStatus(getRawList(), s, this);
    }

    /**
     * Implements IRequestQueue.releaseRequest
     * <p>
     *
     * @see IRequestQueue#releaseRequest
     */
    public final void releaseRequest(IRequest request) {
        // mTable.unlock(request.getRequestId());
    }

    public void updateRequest(IRequest r) {
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

    public INotify getPendingNotify() {
        return mPendingNotify;
    }

    // Constructor
    protected ARequestQueue(IPolicy policy, IService service, INotify notify,
            INotify pendingNotify) {
        mPolicy = policy;
        mService = service;
        mNotify = notify;
        mPendingNotify = pendingNotify;
    }

    // Instance variables
    // RequestIDTable mTable = new RequestIDTable();

    IPolicy mPolicy;
    IService mService;
    INotify mNotify;
    INotify mPendingNotify;
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
