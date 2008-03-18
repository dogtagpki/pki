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


import java.io.*;
import java.net.*;
import java.util.*;
import java.math.*;
import java.security.*;
import java.security.cert.*;
import netscape.security.x509.*;
import netscape.security.util.*;

import com.netscape.certsrv.base.*;
import com.netscape.certsrv.policy.*;
import com.netscape.certsrv.connector.*;
import com.netscape.certsrv.publish.*;
import com.netscape.certsrv.request.*;


/**
 * An interface representing a RA request services.
 * <P>
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
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
