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
    public static String BEGIN_STRING = "begin";
    public static String PENDING_STRING = "pending";
    public static String APPROVED_STRING = "approved";
    public static String SVC_PENDING_STRING = "svc_pending";
    public static String CANCELED_STRING = "canceled";
    public static String REJECTED_STRING = "rejected";
    public static String COMPLETE_STRING = "complete";

    /**
     * The initial state of a request. Requests in this state have not
     * been review by policy.
     *
     * While in this state the source of the request (usually the servlet,
     * but it could be some other protocol module, such as email)
     * should populate the request with data need to service it.
     */
    public static RequestStatus BEGIN = new RequestStatus(BEGIN_STRING);

    /**
     * The state of a request that is waiting for action by an agent.
     * When the agent approves or rejects the request, process will
     * continue as appropriate.
     *
     * In this state there may be PolicyMessages present that indicate
     * the reason for the pending status.
     */
    public static RequestStatus PENDING = new RequestStatus(PENDING_STRING);

    /**
     * The state of a request that has been approved by an agent, or
     * automatically by the policy engine, but have not been successfully
     * transmitted to the service module.
     *
     * These requests are resent to the service during the recovery
     * process that runs at server startup.
     */
    public static RequestStatus APPROVED = new RequestStatus(APPROVED_STRING);

    /**
     * The state of a request that has been sent to the service, but
     * has not been fully processed. The service will invoke the
     * serviceComplete() method to cause processing to continue.
     */
    public static RequestStatus SVC_PENDING =
            new RequestStatus(SVC_PENDING_STRING);

    /**
     * Not implemented. This is intended to be a final state that is
     * reached when a request is removed from the processing queue without
     * normal notification occurring. (see REJECTED)
     */
    public static RequestStatus CANCELED = new RequestStatus(CANCELED_STRING);

    /**
     * The state of a request after it is rejected. When a request is
     * rejected, the notifier is called prior to making the finl status
     * change.
     *
     * Rejected requests may have PolicyMessages indicating the reason for
     * the rejection, or AgentMessages, which allow the agent to give
     * reasons for the action.
     */
    public static RequestStatus REJECTED = new RequestStatus(REJECTED_STRING);

    /**
     * The normal final state of a request. The completion status attribute
     * gives other information about the request. The request is not
     * necessarily successful, but may indicated that service processing
     * did not succeed.
     */
    public static RequestStatus COMPLETE = new RequestStatus(COMPLETE_STRING);

    /**
     * Converts a string name for a request status into the
     * request status enum object.
     * <p>
     *
     * @param s
     *            The string representation of the state.
     * @return
     *         request status
     */
    public static RequestStatus fromString(String s) {
        if (s.equals(BEGIN_STRING))
            return BEGIN;
        if (s.equals(PENDING_STRING))
            return PENDING;
        if (s.equals(APPROVED_STRING))
            return APPROVED;
        if (s.equals(SVC_PENDING_STRING))
            return SVC_PENDING;
        if (s.equals(CANCELED_STRING))
            return CANCELED;
        if (s.equals(REJECTED_STRING))
            return REJECTED;
        if (s.equals(COMPLETE_STRING))
            return COMPLETE;

        return null;
    }

    /**
     * Returns the string form of the RequestStatus, which may be used
     * to record the status in a database.
     *
     * @return request status
     */
    public String toString() {
        return mString;
    }

    /**
     * Class constructor. Creates request status from the string.
     *
     * @param string string describing request status
     */
    private RequestStatus(String string) {
        mString = string;
    }

    private String mString;

    /**
     * Compares request status with specified string.
     *
     * @param string string describing request status
     */
    public boolean equals(String string) {
        if (string.equals(mString))
            return true;
        else
            return false;
    }

    /**
     * Compares current request status with request status.
     *
     * @param rs request status
     */
    public boolean equals(RequestStatus rs) {
        if (mString.equals(rs.mString))
            return true;
        else
            return false;
    }
}
