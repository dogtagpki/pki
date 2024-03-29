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
package com.netscape.certsrv.client.connection;

import java.io.IOException;
import java.net.UnknownHostException;

/**
 * Interface for all connection factory. Primarily act as
 * the abstraction layer for different kind of connection factory.
 *
 * @version $Revision$, $Date$
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated(since="10.14.0", forRemoval=true)
public interface IConnectionFactory {

    /**
     * Creates connection using the host and port
     *
     * @param host The host to connect to
     * @param port The port to connect to
     * @return The created connection
     * @throws IOException On an IO Error
     * @throws UnknownHostException If the host can't be resolved
     */
    public IConnection create(String host, int port)
            throws IOException, UnknownHostException;

}
