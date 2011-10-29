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


import java.util.*;
import java.math.*;
import java.security.*;
import java.net.*;
import java.io.*;


public class LoginServiceAttribute extends Attribute {
    public static final int TELNET = 0;
    public static final int RLOGIN = 1;
    public static final int TCP_CLEAR = 2;
    public static final int PORTMASTER = 3;
    public static final int LAT = 4;
    public static final int X25_PAD = 5;
    public static final int X25_T3POS = 6;
    public static final int TCP_CLEAR_QUIET = 8;

    private byte _value[] = null;
    private int _type = 0;

    public LoginServiceAttribute(byte value[]) {
        super();
        _t = LOGIN_SERVICE;
        _type = value[5] & 0xFF;
        _type |= ((value[4] << 8) & 0xFF00);
        _type |= ((value[3] << 16) & 0xFF0000);
        _type |= ((value[2] << 24) & 0xFF000000);
        _value = value;
    }

    public int getType() {
        return _type;
    }

    public byte[] getValue() throws IOException {
        byte[] p = new byte[4];

        p[0] = (byte) ((_type >>> 24) & 0xFF);
        p[1] = (byte) ((_type >>> 16) & 0xFF);
        p[2] = (byte) ((_type >>> 8) & 0xFF);
        p[3] = (byte) (_type & 0xFF);
        return p;
    }
}
