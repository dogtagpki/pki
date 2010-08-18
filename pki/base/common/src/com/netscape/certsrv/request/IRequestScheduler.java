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
package com.netscape.certsrv.request;


//import java.io.Serializable;

import java.util.Date;
import java.util.Enumeration;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IAttrSet;


/**
 * This is an interface to a request scheduler that prioritizes
 * the threads based on the request processing order.
 * The request that enters the request queue first should
 * be processed first.
 * 
 * @version $Revision$ $Date$
 */
public interface IRequestScheduler {

    /**
     * Request entered the request queue processing.
     *
     * @param r request
     */
    public void requestIn(IRequest r);

    /**
     * Request exited the request queue processing.
     *
     * @param r request
     */
    public void requestOut(IRequest r);
}
