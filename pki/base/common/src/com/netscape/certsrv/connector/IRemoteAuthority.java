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


import com.netscape.certsrv.base.*;


/**
 * This represents a remote authority that can be
 * a certificate manager, or key recovery manager or
 * some other manager.
 *
 * @version $Revision$, $Date$
 */
public interface IRemoteAuthority {

    /**
     * Retrieves the host name of the remote Authority.
     * @return String with the name of host of remote Authority.
     */
    public String getHost();

    /**
     * Retrieves the port number of the remote Authority.
     * @return Int with port number of remote Authority.
     */
    public int getPort();

    /**
     * Retrieves the URI of the remote Authority.
     * @return String with URI of remote Authority.
     */
    public String getURI();

    /**
     * Retrieves the timeout value for the connection to the remote Authority.
     * @return In with remote Authority timeout value.
     */
    public int getTimeout();
}
