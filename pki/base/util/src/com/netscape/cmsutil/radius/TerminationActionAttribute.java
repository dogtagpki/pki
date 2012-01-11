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

public class TerminationActionAttribute extends Attribute {
    public static final int DEFAULT = 0;
    public static final int RADIUS_REQUEST = 1;

    private int _action = 0;

    public TerminationActionAttribute(byte value[]) {
        super();
        _t = TERMINATION_ACTION;
        _action = value[5] & 0xFF;
        _action |= ((value[4] << 8) & 0xFF00);
        _action |= ((value[3] << 16) & 0xFF0000);
        _action |= ((value[2] << 24) & 0xFF000000);
    }

    public TerminationActionAttribute(int action) {
        super(TERMINATION_ACTION);
        _action = action;
    }

    public int getAction() {
        return _action;
    }

    public byte[] getValue() throws IOException {
        byte[] p = new byte[4];

        p[0] = (byte) ((_action >>> 24) & 0xFF);
        p[1] = (byte) ((_action >>> 16) & 0xFF);
        p[2] = (byte) ((_action >>> 8) & 0xFF);
        p[3] = (byte) (_action & 0xFF);
        return p;
    }
}
