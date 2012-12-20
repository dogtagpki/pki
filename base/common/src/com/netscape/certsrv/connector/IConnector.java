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
package com.netscape.certsrv.connector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.request.IRequest;

/**
 * This interface represents a connector that forwards
 * CMS requests to a remote authority.
 *
 * To register a connector, one can add the following
 * to the CMS.cfg:
 *
 * <pre>
 *
 *  Example for KRA type connector.
 * ca.connector.KRA.enable=true
 * ca.connector.KRA.host=thehost.netscape.com        #Remote host.
 * ca.connector.KRA.port=1974                        #Remote host port.
 * ca.connector.KRA.nickName="cert-kra"              #Nickname of connector for identity purposes.
 * ca.connector.KRA.uri="/kra/connector"             #Uri of the KRA server.
 * ca.connector.KRA.id="kra"
 * ca.connector.KRA.minHttpConns=1                   #Min connection pool connections.
 * ca.connector.KRA.maxHttpConns=10                  #Max connection pool connections.
 * </pre>
 *
 * @version $Revision$, $Date$
 */
public interface IConnector {

    /**
     * Sends the request to a remote authority.
     *
     * @param req Request to be forwarded to remote authority.
     * @return true for success, otherwise false.
     * @exception EBaseException Failure to send request to remote authority.
     */
    public boolean send(IRequest req)
            throws EBaseException;

    /**
     * Starts this connector.
     */
    public void start();

    /**
     * Stop the connector.
     */
    public void stop();
}
