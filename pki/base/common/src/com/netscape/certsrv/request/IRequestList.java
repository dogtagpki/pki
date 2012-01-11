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

import java.util.Enumeration;

/**
 * An interface providing a list of RequestIds that match
 * some criteria. It could be a list of all elements in a
 * queue, or just some defined sub-set.
 * 
 * @version $Revision$, $Date$
 */
public interface IRequestList
        extends Enumeration {

    /**
     * Gets the next RequestId from this list. null is
     * returned when there are no more elements in the list.
     * <p>
     * Callers should be sure there is another element in the list by calling hasMoreElements first.
     * <p>
     * 
     * @return next request id
     */
    RequestId nextRequestId();

    /**
     * Gets next request from the list.
     * 
     * @return next request
     */
    public Object nextRequest();

    /**
     * Gets next request Object from the list.
     * 
     * @return next request
     */
    public IRequest nextRequestObject();
}
