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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.common;

/**
 * This represents a user request.
 *
 * @version $Revision$, $Date$
 */
public interface ICMSRequest {

    // statuses. the first two are out of band.
    public static final Integer UNAUTHORIZED = Integer.valueOf(1);
    public static final Integer SUCCESS = Integer.valueOf(2);
    public static final Integer PENDING = Integer.valueOf(3);
    public static final Integer SVC_PENDING = Integer.valueOf(4);
    public static final Integer REJECTED = Integer.valueOf(5);
    public static final Integer ERROR = Integer.valueOf(6);
    public static final Integer EXCEPTION = Integer.valueOf(7); // unexpected error.

}
