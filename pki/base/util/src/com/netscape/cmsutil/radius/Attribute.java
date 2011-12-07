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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public abstract class Attribute {
    public static final int USER_NAME = 1;
    public static final int USER_PASSWORD = 2;
    public static final int CHAP_PASSWORD = 3;
    public static final int NAS_IP_ADDRESS = 4;
    public static final int NAS_PORT = 5;
    public static final int SERVICE_TYPE = 6;
    public static final int FRAMED_PROTOCOL = 7;
    public static final int FRAMED_IP_ADDRESS = 8;
    public static final int FRAMED_IP_NETMASK = 9;
    public static final int FRAMED_ROUTING = 10;
    public static final int FILTER_ID = 11;
    public static final int FRAMED_MTU = 12;
    public static final int FRAMED_COMPRESSION = 13;
    public static final int LOGIN_IP_HOST = 14;
    public static final int LOGIN_SERVICE = 15;
    public static final int LOGIN_TCP_PORT = 16;
    // 17 HAS NOT BEEN ASSIGNED
    public static final int REPLY_MESSAGE = 18;
    public static final int CALLBACK_NUMBER = 19;
    public static final int CALLBACK_ID = 20;
    // 21 HAS NOT BEEN ASSIGNED
    public static final int FRAMED_ROUTE = 22;
    public static final int FRAMED_IPX_NETWORK = 23;
    public static final int STATE = 24;
    public static final int NAS_CLASS = 25;
    public static final int VENDOR_SPECIFIC = 26;
    public static final int SESSION_TIMEOUT = 27;
    public static final int IDLE_TIMEOUT = 28;
    public static final int TERMINATION_ACTION = 29;
    public static final int CALLER_STATION_ID = 30;
    public static final int CALLING_STATION_ID = 31;
    public static final int NAS_IDENTIFIER = 32;
    public static final int PROXY_STATE = 33;
    public static final int LOGIN_LAT_SERVICE = 34;
    public static final int LOGIN_LAT_NODE = 35;
    public static final int LOGIN_LAT_GROUP = 36;
    public static final int FRAMED_APPLETALK_LINK = 37;
    public static final int FRAMED_APPLETALK_NETWORK = 38;
    public static final int FRAMED_APPLETALK_ZONE = 39;
    // 40-59 HAS NOT BEEN ASSIGNED
    public static final int CHAP_CHALLENGE = 60;
    public static final int NAS_PORT_TYPE = 61;
    public static final int PORT_LIMIT = 62;
    public static final int LOGIN_LAT_PORT = 63;

    protected int _t = 0;

    public Attribute() {
    }

    public Attribute(int t) {
        _t = t;
    }

    public int getType() {
        return _t;
    }

    public abstract byte[] getValue() throws IOException;

    public byte[] getData() throws IOException {
        ByteArrayOutputStream attrOS = new ByteArrayOutputStream();

        attrOS.write(_t); // type
        byte value[] = getValue();

        attrOS.write(value.length + 2); // length
        attrOS.write(value);

        return attrOS.toByteArray();
    }
}
