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

public class StateAttribute extends Attribute {
    private byte _value[] = null;
    private String _str = null;

    public StateAttribute(String str) {
        _t = STATE;
        _str = str;
    }

    public StateAttribute(byte value[]) {
        super();
        _t = STATE;
        _str = new String(value, 2, value.length - 2);
        _value = value;
    }

    public String getString() {
        return _str;
    }

    public byte[] getValue() throws IOException {
        return _str.getBytes();
    }
}
