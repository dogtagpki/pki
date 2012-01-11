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

import java.io.Serializable;

import com.netscape.certsrv.request.IRequest;

/**
 * Messages that are serialized and go over the wire.
 * It must be serializable, and
 * later will be inherited by CRMF message.
 * 
 * @version $Revision$, $Date$
 */
public interface IPKIMessage extends Serializable {

    /**
     * 
     * Returns status of request.
     * 
     * @return String of request status.
     */
    public String getReqStatus();

    /**
     * Retrieves the request type.
     * 
     * @return String of type of request.
     */
    public String getReqType();

    /**
     * Retrieves the request identifer.
     * 
     * @return String of name of request.
     */
    public String getReqId();

    /**
     * Makes a PKIMessage from a request
     * PKIMessage will be sent to wire.
     * 
     * @param r Request to copy from.
     */
    public void fromRequest(IRequest r);

    /**
     * Copies contents of PKIMessage to the request
     * PKIMessage is from the wire.
     * 
     * @param r Request to copy to.
     */
    public void toRequest(IRequest r);

}
