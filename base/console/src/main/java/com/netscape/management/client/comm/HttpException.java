/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.comm;

import java.net.URL;

public class HttpException extends Exception {
    protected URL url;
    protected String status;
    protected int statusCode; // -1 if unknown, or a HttpManager.HTTP_* constant

    public HttpException(URL _url, String _status, int _statusCode) {
        url = _url;
        status = _status;
        statusCode = _statusCode;
    }

    public String getStatus() {
        return status;
    }

    public URL getURL() {
        return url;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String toString() {
        return "HttpException:\n" + "Response: " + status + "\n" +
                "Status:   " + statusCode + "\n" + "URL:      " + url;
    }
}
