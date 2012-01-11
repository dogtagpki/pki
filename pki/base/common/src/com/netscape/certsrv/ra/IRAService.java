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
package com.netscape.certsrv.ra;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.connector.IConnector;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IService;

/**
 * An interface representing a RA request services.
 * <P>
 * 
 * @version $Revision$, $Date$
 */
public interface IRAService extends IService {

    /**
     * Services request.
     * 
     * @param req request data
     */
    public boolean serviceRequest(IRequest req);

    /**
     * Services profile request.
     * 
     * @param request profile enrollment request information
     * @exception EBaseException failed to service profile enrollment request
     */
    public void serviceProfileRequest(IRequest request)
            throws EBaseException;

    /**
     * Returns CA connector.
     * 
     * @return CA connector
     */
    public IConnector getCAConnector();

    /**
     * Returns KRA connector.
     * 
     * @return KRA connector
     */
    public IConnector getKRAConnector();
}
