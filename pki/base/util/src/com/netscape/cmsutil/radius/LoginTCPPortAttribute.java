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
package com.netscape.cmsutil.radius;

import java.io.IOException;

public class LoginTCPPortAttribute extends Attribute {
    private int _port = 0;

    public LoginTCPPortAttribute(byte value[]) {
        super();
        _t = LOGIN_TCP_PORT;
        _port = value[5] & 0xFF;
        _port |= ((value[4] << 8) & 0xFF00);
        _port |= ((value[3] << 16) & 0xFF0000);
        _port |= ((value[2] << 24) & 0xFF000000);
    }

    public LoginTCPPortAttribute(int port) {
        super(LOGIN_TCP_PORT);
        _port = port;
    }

    public int getPort() {
        return _port;
    }

    public byte[] getValue() throws IOException {
        byte[] p = new byte[4];

        p[0] = (byte) ((_port >>> 24) & 0xFF);
        p[1] = (byte) ((_port >>> 16) & 0xFF);
        p[2] = (byte) ((_port >>> 8) & 0xFF);
        p[3] = (byte) (_port & 0xFF);
        return p;
    }
}
