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
package com.netscape.certsrv.base;
import javax.ws.rs.core.Response;

public class BadRequestException extends PKIException {

    private static final long serialVersionUID = -4784839378360933483L;

    public BadRequestException(String message) {
        super(Response.Status.BAD_REQUEST, message);
    }

    public BadRequestException(String message, Throwable cause) {
        super(Response.Status.BAD_REQUEST, message, cause);
    }

    public BadRequestException(Data data) {
        super(data);
    }

}

