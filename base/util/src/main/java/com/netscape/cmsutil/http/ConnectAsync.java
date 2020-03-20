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
package com.netscape.cmsutil.http;

import java.net.SocketException;

import com.netscape.cmsutil.net.ISocketFactory;

public class ConnectAsync extends Thread {
    String host = null;
    int port = 0;
    ISocketFactory obj = null;

    public ConnectAsync(ISocketFactory sock, String host, int port) {
        super();
        this.host = host;
        this.port = port;
        this.obj = sock;
        setName("ConnectAsync");
    }

    public void run() {
        try {
            obj.makeSocket(host, port);
        } catch (SocketException e) {
            // Stop throwing exception
        } catch (Exception e) {
            // Stop throwing exception
        }
    }
}
