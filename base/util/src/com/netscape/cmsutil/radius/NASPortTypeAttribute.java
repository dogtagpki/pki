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

public class NASPortTypeAttribute extends Attribute {
    public static final int ASYNC = 0;
    public static final int SYNC = 1;
    public static final int ISDN_SYNC = 2;
    public static final int ISDN_ASYNC_V120 = 3;
    public static final int ISDN_ASYNC_V110 = 4;
    public static final int VIRTUAL = 5;
    public static final int PIAFS = 6;
    public static final int HDLC = 7;
    public static final int X_25 = 8;
    public static final int X_75 = 9;
    public static final int G3_FAX = 10;
    public static final int SDSL = 11;
    public static final int ADSL_CAP = 12;
    public static final int ADSL_DMT = 13;
    public static final int IDSL = 14;
    public static final int ETHERNET = 15;
    public static final int XDSL = 16;
    public static final int CABLE = 17;

    private byte _value[] = null;

    public NASPortTypeAttribute(byte value[]) {
        super();
        _t = NAS_PORT_TYPE;
        _value = value;
    }

    public byte[] getValue() throws IOException {
        return _value;
    }
}
