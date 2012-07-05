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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Locale;
import java.util.Set;
import java.util.Vector;

import netscape.security.util.DerInputStream;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.RevokedCertImpl;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509ExtensionException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IAttrSet;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.AgentApprovals;
import com.netscape.certsrv.request.IEnrollmentRequest;
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
     * Implements IRequestQueue.newRequest
     * <p>
     *
     * @see IRequestQueue#newRequest
     */
    public IRequest newRequest(String requestType)
            throws EBaseException {
        if (requestType == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_REQUEST_TYPE", "null"));
        }
        RequestId rId = newRequestId();
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
        ((Request) r).mModificationTime = CMS.getCurrentDate();

        String name = getUserIdentity();

        if (name != null)
            r.setExtData(IRequest.UPDATED_BY, name);

        // TODO: use a state flag to determine whether to call
        // addRequest or modifyRequest (see newRequest as well)
        modifyRequest(r);
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
        if (CMS.isRunningMode()) {
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

        mLogger = CMS.getLogger();
    }

    // Instance variables
    // RequestIDTable mTable = new RequestIDTable();

    IPolicy mPolicy;
    IService mService;
    INotify mNotify;
    INotify mPendingNotify;

    protected ILogger mLogger;
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

//
// Request - implementation of the IRequest interface.  This
// version is returned by ARequestQueue (and its derivatives)
//
class Request implements IRequest {

    private static final long serialVersionUID = -1510479502681392568L;

    // IRequest.getRequestId
    public RequestId getRequestId() {
        return mRequestId;
    }

    // IRequest.getRequestStatus
    public RequestStatus getRequestStatus() {
        return mRequestStatus;
    }

    // Obsolete
    public void setRequestStatus(RequestStatus s) {
        mRequestStatus = s;
        // expose request status so that we can do predicate upon it
        setExtData(IRequest.REQ_STATUS, s.toString());
    }

    public boolean isSuccess() {
        Integer result = getExtDataInInteger(IRequest.RESULT);

        if (result != null && result.equals(IRequest.RES_SUCCESS))
            return true;
        else
            return false;
    }

    public String getError(Locale locale) {
        return getExtDataInString(IRequest.ERROR);
    }

    // IRequest.getSourceId
    public String getSourceId() {
        return mSourceId;
    }

    // IRequest.setSourceId
    public void setSourceId(String id) {
        mSourceId = id;
    }

    // IRequest.getRequestOwner
    public String getRequestOwner() {
        return mOwner;
    }

    // IRequest.setRequestOwner
    public void setRequestOwner(String id) {
        mOwner = id;
    }

    // IRequest.getRequestType
    public String getRequestType() {
        return mRequestType;
    }

    // IRequest.setRequestType
    public void setRequestType(String type) {
        mRequestType = type;
        setExtData(IRequest.REQ_TYPE, type);
    }

    // IRequest.getRequestVersion
    public String getRequestVersion() {
        return getExtDataInString(IRequest.REQ_VERSION);
    }

    // IRequest.getCreationTime
    public Date getCreationTime() {
        return mCreationTime;
    }

    public String getContext() {
        return mContext;
    }

    public void setContext(String ctx) {
        mContext = ctx;
    }

    // IRequest.getModificationTime
    public Date getModificationTime() {
        return mModificationTime;
    }

    /**
     * this isn't that efficient but will do for now.
     */
    public void copyContents(IRequest req) {
        Enumeration<String> e = req.getExtDataKeys();
        while (e.hasMoreElements()) {
            String key = e.nextElement();
            if (!key.equals(IRequest.ISSUED_CERTS) &&
                    !key.equals(IRequest.ERRORS) &&
                    !key.equals(IRequest.REMOTE_REQID)) {
                if (req.isSimpleExtDataValue(key)) {
                    setExtData(key, req.getExtDataInString(key));
                } else {
                    setExtData(key, req.getExtDataInHashtable(key));
                }
            }
        }
    }

    /**
     * This function used to check that the keys obeyed LDAP attribute name
     * syntax rules. Keys are being encoded now, so it is changed to just
     * filter out null and empty string keys.
     *
     * @param key The key to check
     * @return false if invalid
     */
    protected boolean isValidExtDataKey(String key) {
        return key != null &&
                (!key.equals(""));
    }

    protected boolean isValidExtDataHashtableValue(Hashtable<String, String> hash) {
        if (hash == null) {
            return false;
        }
        Enumeration<String> keys = hash.keys();
        while (keys.hasMoreElements()) {
            Object key = keys.nextElement();
            if (!((key instanceof String) && isValidExtDataKey((String) key))) {
                return false;
            }
            /*
             * 	TODO  should the Value type be String?
             */
            Object value = hash.get(key);
            if (!(value instanceof String)) {
                return false;
            }
        }

        return true;
    }

    public boolean setExtData(String key, String value) {
        if (!isValidExtDataKey(key)) {
            return false;
        }
        if (value == null) {
            return false;
        }

        mExtData.put(key, value);
        return true;
    }

    public boolean setExtData(String key, Hashtable<String, String> value) {
        if (!(isValidExtDataKey(key) && isValidExtDataHashtableValue(value))) {
            return false;
        }

        mExtData.put(key, new ExtDataHashtable<String>(value));
        return true;
    }

    public boolean isSimpleExtDataValue(String key) {
        return (mExtData.get(key) instanceof String);
    }

    public String getExtDataInString(String key) {
        Object value = mExtData.get(key);
        if (value == null) {
            return null;
        }
        if (!(value instanceof String)) {
            return null;
        }
        return (String) value;
    }

    @SuppressWarnings("unchecked")
    public Hashtable<String, String> getExtDataInHashtable(String key) {
        Object value = mExtData.get(key);
        if (value == null) {
            return null;
        }
        if (!(value instanceof Hashtable)) {
            return null;
        }
        return new ExtDataHashtable<String>((Hashtable<String, String>) value);
    }

    public Enumeration<String> getExtDataKeys() {
        return mExtData.keys();
    }

    public void deleteExtData(String type) {
        mExtData.remove(type);
    }

    public boolean setExtData(String key, String subkey, String value) {
        if (!(isValidExtDataKey(key) && isValidExtDataKey(subkey))) {
            return false;
        }
        if (isSimpleExtDataValue(key)) {
            return false;
        }
        if (value == null) {
            return false;
        }

        @SuppressWarnings("unchecked")
        Hashtable<String, String> existingValue = (Hashtable<String, String>) mExtData.get(key);
        if (existingValue == null) {
            existingValue = new ExtDataHashtable<String>();
            mExtData.put(key, existingValue);
        }
        existingValue.put(subkey, value);
        return true;
    }

    public String getExtDataInString(String key, String subkey) {
        Hashtable<String, String> value = getExtDataInHashtable(key);
        if (value == null) {
            return null;
        }
        return value.get(subkey);
    }

    public boolean setExtData(String key, Integer value) {
        if (value == null) {
            return false;
        }
        return setExtData(key, value.toString());
    }

    public Integer getExtDataInInteger(String key) {
        String strVal = getExtDataInString(key);
        if (strVal == null) {
            return null;
        }
        try {
            return Integer.valueOf(strVal);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public boolean setExtData(String key, Integer[] data) {
        if (data == null) {
            return false;
        }
        String[] stringArray = new String[data.length];
        for (int index = 0; index < data.length; index++) {
            stringArray[index] = data[index].toString();
        }
        return setExtData(key, stringArray);
    }

    public Integer[] getExtDataInIntegerArray(String key) {
        String[] stringArray = getExtDataInStringArray(key);
        if (stringArray == null) {
            return null;
        }
        Integer[] intArray = new Integer[stringArray.length];
        for (int index = 0; index < stringArray.length; index++) {
            try {
                intArray[index] = new Integer(stringArray[index]);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return intArray;
    }

    public boolean setExtData(String key, BigInteger value) {
        if (value == null) {
            return false;
        }
        return setExtData(key, value.toString());
    }

    public BigInteger getExtDataInBigInteger(String key) {
        String strVal = getExtDataInString(key);
        if (strVal == null) {
            return null;
        }
        try {
            return new BigInteger(strVal);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public boolean setExtData(String key, BigInteger[] data) {
        if (data == null) {
            return false;
        }
        String[] stringArray = new String[data.length];
        for (int index = 0; index < data.length; index++) {
            stringArray[index] = data[index].toString();
        }
        return setExtData(key, stringArray);
    }

    public BigInteger[] getExtDataInBigIntegerArray(String key) {
        String[] stringArray = getExtDataInStringArray(key);
        if (stringArray == null) {
            return null;
        }
        BigInteger[] intArray = new BigInteger[stringArray.length];
        for (int index = 0; index < stringArray.length; index++) {
            try {
                intArray[index] = new BigInteger(stringArray[index]);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return intArray;
    }

    public boolean setExtData(String key, Throwable e) {
        if (e == null) {
            return false;
        }
        return setExtData(key, e.toString());
    }

    public boolean setExtData(String key, byte[] data) {
        if (data == null) {
            return false;
        }
        return setExtData(key, CMS.BtoA(data));
    }

    public byte[] getExtDataInByteArray(String key) {
        String value = getExtDataInString(key);
        if (value != null) {
            return CMS.AtoB(value);
        }
        return null;
    }

    public boolean setExtData(String key, X509CertImpl data) {
        if (data == null) {
            return false;
        }
        try {
            return setExtData(key, data.getEncoded());
        } catch (CertificateEncodingException e) {
            return false;
        }
    }

    public X509CertImpl getExtDataInCert(String key) {
        byte[] data = getExtDataInByteArray(key);
        if (data != null) {
            try {
                return new X509CertImpl(data);
            } catch (CertificateException e) {
                return null;
            }
        }
        return null;
    }

    public boolean setExtData(String key, X509CertImpl[] data) {
        if (data == null) {
            return false;
        }
        String[] stringArray = new String[data.length];
        for (int index = 0; index < data.length; index++) {
            try {
                stringArray[index] = CMS.BtoA(data[index].getEncoded());
            } catch (CertificateEncodingException e) {
                return false;
            }
        }
        return setExtData(key, stringArray);
    }

    public X509CertImpl[] getExtDataInCertArray(String key) {
        String[] stringArray = getExtDataInStringArray(key);
        if (stringArray == null) {
            return null;
        }
        X509CertImpl[] certArray = new X509CertImpl[stringArray.length];
        for (int index = 0; index < stringArray.length; index++) {
            try {
                certArray[index] = new X509CertImpl(CMS.AtoB(stringArray[index]));
            } catch (CertificateException e) {
                return null;
            }
        }
        return certArray;
    }

    public boolean setExtData(String key, X509CertInfo data) {
        if (data == null) {
            return false;
        }
        try {
            return setExtData(key, data.getEncodedInfo(true));
        } catch (CertificateEncodingException e) {
            return false;
        }
    }

    public X509CertInfo getExtDataInCertInfo(String key) {
        byte[] data = getExtDataInByteArray(key);
        if (data != null) {
            try {
                return new X509CertInfo(data);
            } catch (CertificateException e) {
                return null;
            }
        }
        return null;
    }

    public boolean setExtData(String key, X509CertInfo[] data) {
        if (data == null) {
            return false;
        }
        String[] stringArray = new String[data.length];
        for (int index = 0; index < data.length; index++) {
            try {
                stringArray[index] = CMS.BtoA(data[index].getEncodedInfo(true));
            } catch (CertificateEncodingException e) {
                return false;
            }
        }
        return setExtData(key, stringArray);
    }

    public X509CertInfo[] getExtDataInCertInfoArray(String key) {
        String[] stringArray = getExtDataInStringArray(key);
        if (stringArray == null) {
            return null;
        }
        X509CertInfo[] certArray = new X509CertInfo[stringArray.length];
        for (int index = 0; index < stringArray.length; index++) {
            try {
                certArray[index] = new X509CertInfo(CMS.AtoB(stringArray[index]));
            } catch (CertificateException e) {
                return null;
            }
        }
        return certArray;
    }

    public boolean setExtData(String key, RevokedCertImpl[] data) {
        if (data == null) {
            return false;
        }
        String[] stringArray = new String[data.length];
        for (int index = 0; index < data.length; index++) {
            try {
                stringArray[index] = CMS.BtoA(data[index].getEncoded());
            } catch (CRLException e) {
                return false;
            }
        }
        return setExtData(key, stringArray);
    }

    public RevokedCertImpl[] getExtDataInRevokedCertArray(String key) {
        String[] stringArray = getExtDataInStringArray(key);
        if (stringArray == null) {
            return null;
        }
        RevokedCertImpl[] certArray = new RevokedCertImpl[stringArray.length];
        for (int index = 0; index < stringArray.length; index++) {
            try {
                certArray[index] = new RevokedCertImpl(CMS.AtoB(stringArray[index]));
            } catch (CRLException e) {
                return null;
            } catch (X509ExtensionException e) {
                return null;
            }
        }
        return certArray;
    }

    public boolean setExtData(String key, Vector<?> stringVector) {
        String[] stringArray;
        if (stringVector == null) {
            return false;
        }
        try {
            stringArray = stringVector.toArray(new String[0]);
        } catch (ArrayStoreException e) {
            return false;
        }
        return setExtData(key, stringArray);
    }

    public Vector<String> getExtDataInStringVector(String key) {
        String[] stringArray = getExtDataInStringArray(key);
        if (stringArray == null) {
            return null;
        }
        return new Vector<String>(Arrays.asList(stringArray));
    }

    public boolean getExtDataInBoolean(String key, boolean defVal) {
        String val = getExtDataInString(key);
        if (val == null)
            return defVal;
        return val.equalsIgnoreCase("true") || val.equalsIgnoreCase("ON");
    }

    public boolean getExtDataInBoolean(String prefix, String type, boolean defVal) {
        String val = getExtDataInString(prefix, type);
        if (val == null)
            return defVal;
        return val.equalsIgnoreCase("true") || val.equalsIgnoreCase("ON");
    }

    public boolean setExtData(String key, IAuthToken data) {
        if (data == null) {
            return false;
        }
        Hashtable<String, String> hash = new Hashtable<String, String>();
        Enumeration<String> keys = data.getElements();
        while (keys.hasMoreElements()) {
            try {
                String authKey = keys.nextElement();
                hash.put(authKey, data.getInString(authKey));
            } catch (ClassCastException e) {
                return false;
            }
        }
        return setExtData(key, hash);
    }

    public IAuthToken getExtDataInAuthToken(String key) {
        Hashtable<String, String> hash = getExtDataInHashtable(key);
        if (hash == null) {
            return null;
        }
        AuthToken authToken = new AuthToken(null);
        Enumeration<String> keys = hash.keys();
        while (keys.hasMoreElements()) {
            try {
                String hashKey = keys.nextElement();
                authToken.set(hashKey, hash.get(hashKey));
            } catch (ClassCastException e) {
                return null;
            }
        }
        return authToken;
    }

    public boolean setExtData(String key, CertificateExtensions data) {
        if (data == null) {
            return false;
        }
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        try {
            data.encode(byteStream);
        } catch (CertificateException e) {
            return false;
        } catch (IOException e) {
            return false;
        }
        return setExtData(key, byteStream.toByteArray());
    }

    public CertificateExtensions getExtDataInCertExts(String key) {
        CertificateExtensions exts = null;
        byte[] extensionsData = getExtDataInByteArray(key);
        if (extensionsData != null) {
            exts = new CertificateExtensions();
            try {
                exts.decodeEx(new ByteArrayInputStream(extensionsData));
                // exts.decode() does not work when the CertExts size is 0
                // exts.decode(new ByteArrayInputStream(extensionsData));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return exts;
    }

    public boolean setExtData(String key, CertificateSubjectName data) {
        if (data == null) {
            return false;
        }
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        try {
            data.encode(byteStream);
        } catch (IOException e) {
            return false;
        }
        return setExtData(key, byteStream.toByteArray());
    }

    public CertificateSubjectName getExtDataInCertSubjectName(String key) {
        CertificateSubjectName name = null;
        byte[] nameData = getExtDataInByteArray(key);
        if (nameData != null) {
            try {
                // You must use DerInputStream
                // using ByteArrayInputStream fails
                name = new CertificateSubjectName(
                        new DerInputStream(nameData));
            } catch (IOException e) {
                return null;
            }
        }
        return name;
    }

    public boolean setExtData(String key, String[] values) {
        if (values == null) {
            return false;
        }
        Hashtable<String, String> hashValue = new Hashtable<String, String>();
        for (int index = 0; index < values.length; index++) {
            hashValue.put(Integer.toString(index), values[index]);
        }
        return setExtData(key, hashValue);
    }

    public String[] getExtDataInStringArray(String key) {
        int index;

        Hashtable<String, String> hashValue = getExtDataInHashtable(key);
        if (hashValue == null) {
            String s = getExtDataInString(key);
            if (s == null) {
                return null;
            } else {
                String[] sa = { s };
                return sa;
            }
        }
        Set<String> arrayKeys = hashValue.keySet();
        Vector<Object> listValue = new Vector<Object>(arrayKeys.size());
        for (Iterator<String> iter = arrayKeys.iterator(); iter.hasNext();) {
            String arrayKey = iter.next();
            try {
                index = Integer.parseInt(arrayKey);
            } catch (NumberFormatException e) {
                return null;
            }
            if (listValue.size() < (index + 1)) {
                listValue.setSize(index + 1);
            }
            listValue.set(index,
                    hashValue.get(arrayKey));
        }
        return listValue.toArray(new String[0]);
    }

    public IAttrSet asIAttrSet() {
        return new RequestIAttrSetWrapper(this);
    }

    Request(RequestId id) {
        mRequestId = id;
        setRequestStatus(RequestStatus.BEGIN);
    }

    // instance variables
    protected RequestId mRequestId;
    protected RequestStatus mRequestStatus;
    protected String mSourceId;
    protected String mSource;
    protected String mOwner;
    protected String mRequestType;
    protected String mContext; // string for now.
    protected ExtDataHashtable<Object> mExtData = new ExtDataHashtable<Object>();

    Date mCreationTime = CMS.getCurrentDate();
    Date mModificationTime = CMS.getCurrentDate();
}

class RequestIAttrSetWrapper implements IAttrSet {
    /**
     *
     */
    private static final long serialVersionUID = 8231914824991772682L;
    IRequest mRequest;

    public RequestIAttrSetWrapper(IRequest request) {
        mRequest = request;
    }

    public void set(String name, Object obj) throws EBaseException {
        try {
            mRequest.setExtData(name, (String) obj);
        } catch (ClassCastException e) {
            throw new EBaseException(e.toString());
        }
    }

    public Object get(String name) throws EBaseException {
        return mRequest.getExtDataInString(name);
    }

    public void delete(String name) throws EBaseException {
        mRequest.deleteExtData(name);
    }

    public Enumeration<String> getElements() {
        return mRequest.getExtDataKeys();
    }
}

/**
 * Example of a specialized request class.
 */
class EnrollmentRequest extends Request implements IEnrollmentRequest {

    private static final long serialVersionUID = 8214498908217267555L;

    EnrollmentRequest(RequestId id) {
        super(id);
    }
}

class RequestListByStatus
        implements IRequestList {
    public boolean hasMoreElements() {
        return (mNext != null);
    }

    public Object nextRequest() {
        return null;
    }

    public IRequest nextRequestObject() {
        return null;
    }

    public RequestId nextElement() {
        RequestId next = mNext;

        update();

        return next;
    }

    public RequestId nextRequestId() {
        RequestId next = mNext;

        update();

        return next;
    }

    public RequestListByStatus(Enumeration<RequestId> e, RequestStatus s, IRequestQueue q) {
        mEnumeration = e;
        mStatus = s;
        mQueue = q;

        update();
    }

    protected void update() {
        RequestId rId;

        mNext = null;

        while (mNext == null) {
            if (!mEnumeration.hasMoreElements())
                break;

            rId = mEnumeration.nextElement();

            try {
                IRequest r = mQueue.findRequest(rId);

                if (r.getRequestStatus() == mStatus)
                    mNext = rId;

                mQueue.releaseRequest(r);
            } catch (Exception e) {
            }
        }
    }

    protected RequestStatus mStatus;
    protected IRequestQueue mQueue;
    protected Enumeration<RequestId> mEnumeration;
    protected RequestId mNext;
}

class RequestList
        implements IRequestList {
    public boolean hasMoreElements() {
        return mEnumeration.hasMoreElements();
    }

    public RequestId nextElement() {
        return mEnumeration.nextElement();
    }

    public RequestId nextRequestId() {
        return mEnumeration.nextElement();
    }

    public Object nextRequest() {
        return null;
    }

    public IRequest nextRequestObject() {
        return null;
    }

    public RequestList(Enumeration<RequestId> e) {
        mEnumeration = e;
    }

    protected Enumeration<RequestId> mEnumeration;
}

class RecoverThread extends Thread {
    private ARequestQueue mQ = null;

    public RecoverThread(ARequestQueue q) {
        mQ = q;
        setName("RequestRecoverThread");
    }

    public void run() {
        mQ.recoverWillBlock();
    }
}
