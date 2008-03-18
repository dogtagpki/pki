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


import com.netscape.certsrv.base.EBaseException;


/**
 * This interface defines how requests are serviced.
 * This covers certificate generation, revocation, renewals,
 * revocation checking, and much more.
 * <p>
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public interface IService {

    /**
     * Performs the service (such as certificate generation)
     * represented by this request.
     * <p>
     * @param request
     *    The request that needs service.  The service may use
     *    attributes stored in the request, and may update the
     *    values, or store new ones.
     * @return
     *    an indication of whether this request is still pending.
     *    'false' means the request will wait for further notification.
     * @exception EBaseException indicates major processing failure.
     */
    boolean serviceRequest(IRequest request)
        throws EBaseException;
}
