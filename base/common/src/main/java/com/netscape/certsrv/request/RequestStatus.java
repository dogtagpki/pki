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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The RequestStatus class represents the current state of a request
 * in a request queue. The state of the request changes as actions
 * are performed on it.
 *
 * The request is created in the BEGIN state, then general progresses
 * through the PENDING, APPROVED, SVC_PENDING, and COMPLETE states.
 * Some requests may bypass the PENDING state if no agent action is
 * required.
 *
 * Requests may be CANCELED (not implemented) or REJECTED. These are
 * error conditions, and usually result because the request was invalid
 * or was not approved by an agent.
 *
 * @version $Revision$ $Date$
 */
public final class RequestStatus implements Serializable {

    private static final long serialVersionUID = -8176052970922133411L;

    public static final Collection<RequestStatus> INSTANCES = new ArrayList<RequestStatus>();
    public static final Map<String, RequestStatus> LABELS = new LinkedHashMap<String, RequestStatus>();

    /**
     * The initial state of a request. Requests in this state have not
     * been review by policy.
     *
     * While in this state the source of the request (usually the servlet,
     * but it could be some other protocol module, such as email)
     * should populate the request with data need to service it.
     */
    public static RequestStatus BEGIN = new RequestStatus("begin");

    /**
     * The state of a request that is waiting for action by an agent.
     * When the agent approves or rejects the request, process will
     * continue as appropriate.
     *
     * In this state there may be PolicyMessages present that indicate
     * the reason for the pending status.
     */
    public static RequestStatus PENDING = new RequestStatus("pending");

    /**
     * The state of a request that has been approved by an agent, or
     * automatically by the policy engine, but have not been successfully
     * transmitted to the service module.
     *
     * These requests are resent to the service during the recovery
     * process that runs at server startup.
     */
    public static RequestStatus APPROVED = new RequestStatus("approved");

    /**
     * The state of a request that has been sent to the service, but
     * has not been fully processed. The service will invoke the
     * serviceComplete() method to cause processing to continue.
     */
    public static RequestStatus SVC_PENDING = new RequestStatus("svc_pending");

    /**
     * Not implemented. This is intended to be a final state that is
     * reached when a request is removed from the processing queue without
     * normal notification occurring. (see REJECTED)
     */
    public static RequestStatus CANCELED = new RequestStatus("canceled");

    /**
     * The state of a request after it is rejected. When a request is
     * rejected, the notifier is called prior to making the finl status
     * change.
     *
     * Rejected requests may have PolicyMessages indicating the reason for
     * the rejection, or AgentMessages, which allow the agent to give
     * reasons for the action.
     */
    public static RequestStatus REJECTED = new RequestStatus("rejected");

    /**
     * The normal final state of a request. The completion status attribute
     * gives other information about the request. The request is not
     * necessarily successful, but may indicated that service processing
     * did not succeed.
     */
    public static RequestStatus COMPLETE = new RequestStatus("complete");

    private String label;

    /**
     * Class constructor. Creates request status from the string.
     *
     * @param label string describing request status
     */
    private RequestStatus(String label) {
        this.label = label;

        INSTANCES.add(this);
        LABELS.put(label.toLowerCase(), this);
    }

    /**
     * Converts a string name for a request status into the
     * request status enum object.
     * <p>
     *
     * @param label
     *            The string representation of the state.
     * @return
     *         request status
     */
    public static RequestStatus fromString(String label) {
        return valueOf(label);
    }

    public static RequestStatus valueOf(String label) {
        return LABELS.get(label.toLowerCase());
    }

    /**
     * Returns the string form of the RequestStatus, which may be used
     * to record the status in a database.
     *
     * @return request status
     */
    public String toString() {
        return label;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((label == null) ? 0 : label.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        RequestStatus other = (RequestStatus) obj;
        if (label == null) {
            if (other.label != null)
                return false;
        } else if (!label.equals(other.label))
            return false;
        return true;
    }
}
