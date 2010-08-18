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


import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.connector.*;
import java.util.*;
import java.io.*;


/**
 * This represents a  Http PKI message. It contains 
 * simple name/value pair values.  Also maintains information
 * about the status and type of the message.
 *
 * @version $Revision$, $Date$
 */
public interface IHttpPKIMessage extends IPKIMessage {

    /**
     * Retrieves the request type.
     * @return String with the type of request.
     */
    public String getReqType();

    /**
     * Retrieves the request identifier.
     * @return String of name of request.
     */
    public String getReqId();

    /**
     * Copies contents of request to make a simple name/value message.
     * @param r Instance of IRequest to be copied from.
     */
    public void fromRequest(IRequest r);

    /**
     * Copies contents to request.
     * @param r Instance of IRequest to be copied to.
     */
    public void toRequest(IRequest r);
}
