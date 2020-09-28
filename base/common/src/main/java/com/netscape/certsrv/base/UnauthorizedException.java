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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.base;

import javax.ws.rs.core.Response;


/**
 * @author Endi S. Dewata
 */
public class UnauthorizedException extends PKIException {

    private static final long serialVersionUID = -2025082875126996556L;

    public UnauthorizedException(String message) {
        super(Response.Status.UNAUTHORIZED, message);
    }

    public UnauthorizedException(String message, Throwable cause) {
        super(Response.Status.UNAUTHORIZED, message, cause);
    }

    public UnauthorizedException(Data data) {
        super(data);
    }

}

