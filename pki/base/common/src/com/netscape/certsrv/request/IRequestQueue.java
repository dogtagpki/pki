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

import java.math.BigInteger;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.repository.IRepository;

/**
 * The IRequestQueue interface defines the operations on
 * a collection of requests within the certificate server.
 * There are may several collections, such as KRA, RA and CA
 * requests. Each of these request collection has a defined
 * set of policies, a notification service (for request
 * completion) and a service routine. The request queue
 * provides an interface for creating and viewing requests,
 * as well as performing operations on them.
 * <p>
 * 
 * @version $Revision$ $Date$
 */
public interface IRequestQueue {

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
    public IRequest newRequest(String requestType)
            throws EBaseException;

    /**
     * Clones a request object. A new request id is assigned
     * and all attributes of the request is copied to cloned request,
     * except for the sourceID of the original request
     * (remote authority's request Id).
     * <p>
     * The cloned request that is returned is LOCKED. The caller MUST release the request object by calling releaseRequest().
     * 
     * @param r request to be cloned
     * @return cloned request
     * @exception EBaseException failed to clone request
     */
    public IRequest cloneRequest(IRequest r)
            throws EBaseException;

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
            throws EBaseException;

    /**
     * Begins processing for this request. This call
     * is valid only on requests with status BEGIN
     * An error is generated for other cases.
     * 
     * @param req request to be processed
     * @exception EBaseException failed to process request
     */
    public void processRequest(IRequest req)
            throws EBaseException;

    /**
     * Sets request scheduler.
     * 
     * @param scheduler request scheduler
     */
    public void setRequestScheduler(IRequestScheduler scheduler);

    /**
     * Gets request scheduler.
     * 
     * @return request scheduler
     */
    public IRequestScheduler getRequestScheduler();

    /**
     * Puts a new request into the PENDING state. This call is
     * only valid for requests with status BEGIN. An error is
     * generated for other cases.
     * <p>
     * This call might be used by agent servlets that want to copy a previous request, and resubmit it. By putting it into PENDING state, the normal agent screens can be used for further processing.
     * 
     * @param req
     *            the request to mark PENDING
     * @exception EBaseException failed to mark request as pending
     */
    public void markRequestPending(IRequest req)
            throws EBaseException;

    /**
     * Clones a request object and mark it pending. A new request id is assigned
     * and all attributes of the request is copied to cloned request,
     * except for the sourceID of the original request
     * (remote authority's request Id).
     * <p>
     * The cloned request that is returned is LOCKED. The caller MUST release the request object by calling releaseRequest().
     * 
     * @param r request to be cloned
     * @return cloned request mark PENDING
     * @exception EBaseException failed to clone or mark request
     */
    public IRequest cloneAndMarkPending(IRequest r)
            throws EBaseException;

    /**
     * Approves a request. The request must be locked.
     * <p>
     * This call will fail if: the request is not in PENDING state the policy modules do not accept the request
     * <p>
     * If the policy modules reject the request, then the request will remain in the PENDING state. Messages from the policy module can be display to the agent to indicate the source of the problem.
     * <p>
     * The request processing code adds an AgentApproval to this request that contains the authentication id of the agent. This data is retrieved from the Session object (qv).
     * 
     * @param request
     *            the request that is being approved
     * @exception EBaseException failed to approve request
     */
    public void approveRequest(IRequest request)
            throws EBaseException;

    /**
     * Rejects a request. The request must be locked.
     * <p>
     * This call will fail if: the request is not in PENDING state
     * <p>
     * The agent servlet (or other application) may wish to store AgentMessage values to indicate the reason for the action
     * 
     * @param request
     *            the request that is being rejected
     * @exception EBaseException failed to reject request
     */
    public void rejectRequest(IRequest request)
            throws EBaseException;

    /**
     * Cancels a request. The request must be locked.
     * <p>
     * This call will fail if: the request is not in PENDING state
     * <p>
     * The agent servlet (or other application) may wish to store AgentMessage values to indicate the reason for the action
     * 
     * @param request
     *            the request that is being canceled
     * @exception EBaseException failed to cancel request
     */
    public void cancelRequest(IRequest request)
            throws EBaseException;

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
    public void updateRequest(IRequest request)
            throws EBaseException;

    /**
     * Returns an enumerator that lists all RequestIds in the
     * queue. The caller should use the RequestIds to locate
     * each request by calling findRequest().
     * <p>
     * NOTE: This interface will not be useful for large databases. This needs to be replace by a VLV (paged) search object.
     * 
     * @return request list
     */
    public IRequestList listRequests();

    /**
     * Returns an enumerator that lists all RequestIds for requests
     * that are in the given status. For example, all the PENDING
     * requests could be listed by specifying RequestStatus.PENDING
     * as the <i>status</i> argument
     * <p>
     * NOTE: This interface will not be useful for large databases. This needs to be replace by a VLV (paged) search object.
     * 
     * @param status request status
     * @return request list
     */
    public IRequestList listRequestsByStatus(RequestStatus status);

    /**
     * Returns an enumerator that lists all RequestIds for requests
     * that match the filter.
     * <p>
     * NOTE: This interface will not be useful for large databases. This needs to be replace by a VLV (paged) search object.
     * 
     * @param filter search filter
     * @return request list
     */
    public IRequestList listRequestsByFilter(String filter);

    /**
     * Returns an enumerator that lists all RequestIds for requests
     * that match the filter.
     * <p>
     * NOTE: This interface will not be useful for large databases. This needs to be replace by a VLV (paged) search object.
     * 
     * @param filter search filter
     * @param maxSize max size to return
     * @return request list
     */
    public IRequestList listRequestsByFilter(String filter, int maxSize);

    /**
     * Returns an enumerator that lists all RequestIds for requests
     * that match the filter.
     * <p>
     * NOTE: This interface will not be useful for large databases. This needs to be replace by a VLV (paged) search object.
     * 
     * @param filter search filter
     * @param maxSize max size to return
     * @param timeLimit timeout value for the search
     * @return request list
     */
    public IRequestList listRequestsByFilter(String filter, int maxSize, int timeLimit);

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
    public RequestId findRequestBySourceId(String id);

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
    public IRequestList findRequestsBySourceId(String id);

    /**
     * Releases the LOCK on a request obtained from findRequest() or
     * newRequest()
     * <p>
     * 
     * @param r request
     */
    public void releaseRequest(IRequest r);

    /**
     * Marks as serviced after destination authority has serviced request.
     * Used by connector.
     * 
     * @param r request
     */
    public void markAsServiced(IRequest r);

    /**
     * Resends requests
     */
    public void recover();

    /**
     * Gets a pageable list of IRequest entries in this queue.
     * 
     * @param pageSize page size
     * @return request list
     */
    public IRequestVirtualList getPagedRequests(int pageSize);

    /**
     * Gets a pageable list of IRequest entries in this queue.
     * 
     * @param filter search filter
     * @param pageSize page size
     * @param sortKey the attributes to sort by
     * @return request list
     */
    public IRequestVirtualList getPagedRequestsByFilter(String filter,
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
    public IRequestVirtualList getPagedRequestsByFilter(RequestId fromId,
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
    public IRequestVirtualList getPagedRequestsByFilter(RequestId fromId,
                                   boolean jumpToEnd, String filter,
                                   int pageSize,
                                   String sortKey);

    /**
     * Retrieves the notifier for pending request.
     * 
     * @return notifier for pending request
     */
    public INotify getPendingNotify();

    public BigInteger getLastRequestIdInRange(BigInteger reqId_low_bound, BigInteger reqId_upper_bound);

    /**
     * Resets serial number.
     */
    public void resetSerialNumber(BigInteger serial) throws EBaseException;

    /**
     * Removes all objects with this repository.
     */
    public void removeAllObjects() throws EBaseException;

    /**
     * Gets request repository.
     * 
     * @return request repository
     */
    public IRepository getRequestRepository();

    public String getPublishingStatus();

    public void setPublishingStatus(String status);
}
