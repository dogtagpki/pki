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

import java.io.IOException;

/**
 * This represents a rquest encoder that serializes and
 * deserializes a request to a Remote Authority so that it can be sent through
 * the connector.
 *
 * @version $Revision$, $Date$
 */
public interface IRequestEncoder {

    /**
     * Encodes a request object.
     *
     * @param r Object to serve as the source of the message.
     * @return String containing encoded message.
     * @exception IOException Failure of the encoding operation due to IO error.
     */
    String encode(Object r)
            throws IOException;

    /**
     * Dncodes a String into an object.
     *
     * @return Object which is the result of the decoded message.
     * @exception IOException Failure of the decoding operation due to IO error.
     */
    Object decode(String s)
            throws IOException;
}
