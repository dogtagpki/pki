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

/**
 * Interface to a policy. The policy evaluates the request for
 * correctness and completeness. It may change or add to values
 * stored in the request. The policy object also decides
 * whether a request should be queue to await approval by
 * an agent.
 * FUTURE: In this case, the policy should set the
 * 'agentGroup' entry in the request to indicate the group
 * of agents allowed to perform further processing. If none
 * is set, a default value ("defaultAgentGroup") will be
 * set instead.
 *
 * @version $Revision$, $Date$
 */
public interface IPolicy {

    /**
     * Applies the policy check to the request. The policy should
     * determine whether the request can be processed immediately,
     * or should be held pending manual approval.
     * <p>
     * The policy can update fields in the request, to add additional values or to restrict the values to pre-determined
     * ranges.
     * <p>
     *
     * @param request
     *            the request to check
     * @return
     *         a result code indicating the result of the evaluation. The
     *         processor will determine the next request processing step based
     *         on this value
     */
    PolicyResult apply(IRequest request);
}
