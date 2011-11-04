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


/**
 * This represents a HTTP connection to a remote authority.
 * Http connection is used by the connector to send
 * PKI messages to a remote authority. The remote authority
 * will reply with a PKI message as well. An example would
 * be the communication between a CA and a KRA.
 *
 * @version $Revision$, $Date$
 */
public interface IHttpConnection {

    /**
     * Sends the PKI message to the remote authority.
     * @param tomsg Message to forward to authority.
     * @exception EBaseException Failed to send message.
     */
    public IPKIMessage send(IPKIMessage tomsg) 
        throws EBaseException;
}
