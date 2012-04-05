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
package com.netscape.certsrv.ocsp;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmsutil.ocsp.OCSPRequest;
import com.netscape.cmsutil.ocsp.OCSPResponse;

/**
 * This class represents the servlet that serves the Online Certificate
 * Status Protocol (OCSP) requests.
 *
 * @version $Revision$ $Date$
 */
public interface IOCSPService {
    /**
     * This method validates the information associated with the specified
     * OCSP request and returns an OCSP response.
     * <P>
     *
     * @param r an OCSP request
     * @return OCSPResponse the OCSP response associated with the specified
     *         OCSP request
     * @exception EBaseException an error associated with the inability to
     *                process the supplied OCSP request
     */
    public OCSPResponse validate(OCSPRequest r)
            throws EBaseException;

    /**
     * Returns the in-memory count of the processed OCSP requests.
     *
     * @return number of processed OCSP requests in memory
     */
    public long getNumOCSPRequest();

    /**
     * Returns the in-memory time (in mini-second) of
     * the processed time for OCSP requests.
     *
     * @return processed times for OCSP requests
     */
    public long getOCSPRequestTotalTime();

    /**
     * Returns the in-memory time (in mini-second) of
     * the signing time for OCSP requests.
     *
     * @return processed times for OCSP requests
     */
    public long getOCSPTotalSignTime();

    public long getOCSPTotalLookupTime();

    /**
     * Returns the total data signed
     * for OCSP requests.
     *
     * @return processed times for OCSP requests
     */
    public long getOCSPTotalData();
}
