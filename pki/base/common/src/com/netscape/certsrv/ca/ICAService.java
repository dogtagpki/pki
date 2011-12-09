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
package com.netscape.certsrv.ca;


import netscape.security.x509.RevokedCertImpl;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.connector.IConnector;
import com.netscape.certsrv.request.IRequest;


/**
 * An interface representing a CA request services.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public interface ICAService {

    /**
     * Marks certificate record as revoked by adding revocation information.
     * Updates CRL cache.
     *
     * @param crlentry revocation information obtained from revocation request
     * @exception EBaseException failed to mark certificate record as revoked
     */
    public void revokeCert(RevokedCertImpl crlentry)
        throws EBaseException;

    /**
     * Marks certificate record as revoked by adding revocation information.
     * Updates CRL cache.
     *
     * @param crlentry revocation information obtained from revocation request
     * @param requestId revocation request id
     * @exception EBaseException failed to mark certificate record as revoked
     */
    public void revokeCert(RevokedCertImpl crlentry, String requestId)
        throws EBaseException;

    /**
     * Issues certificate base on enrollment information,
     * creates certificate record, and stores all necessary data.
     *
     * @param certi information obtain from revocation request
     * @exception EBaseException failed to issue certificate or create certificate record
     */
    public X509CertImpl issueX509Cert(X509CertInfo certi)
        throws EBaseException;

    public X509CertImpl issueX509Cert(X509CertInfo certi, String profileId, String rid)
        throws EBaseException;

    /**
     * Services profile request.
     *
     * @param request profile enrollment request information
     * @exception EBaseException failed to service profile enrollment request
     */
    public void serviceProfileRequest(IRequest request)
        throws EBaseException;

    /**
     * Returns KRA-CA connector.
     *
     * @return KRA-CA connector
     */
    public IConnector getKRAConnector();

    public void setKRAConnector(IConnector c);

    public IConnector getConnector(IConfigStore cs)  throws EBaseException;
}
