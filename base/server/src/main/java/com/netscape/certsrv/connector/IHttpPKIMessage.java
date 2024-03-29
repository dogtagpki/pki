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

import com.netscape.cmscore.request.Request;

/**
 * This represents a Http PKI message. It contains
 * simple name/value pair values. Also maintains information
 * about the status and type of the message.
 *
 * @version $Revision$, $Date$
 */
public interface IHttpPKIMessage extends IPKIMessage {

    /**
     * Retrieves the request type.
     *
     * @return String with the type of request.
     */
    @Override
    public String getReqType();

    /**
     * Retrieves the request identifier.
     *
     * @return String of name of request.
     */
    @Override
    public String getReqId();

    /**
     * Copies contents of request to make a simple name/value message.
     *
     * @param r Instance of Request to be copied from.
     */
    @Override
    public void fromRequest(Request r);

    /**
     * Copies contents to request.
     *
     * @param r Instance of Request to be copied to.
     */
    @Override
    public void toRequest(Request r);
}
