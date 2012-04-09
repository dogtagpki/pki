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

public class CHAPPasswordAttribute extends Attribute {
    private int _ident = 0;
    private String _str = null;

    public CHAPPasswordAttribute(String s) {
        _str = s;
    }

    public CHAPPasswordAttribute(byte value[]) {
        super();
        _t = CHAP_PASSWORD;
        _ident = value[2];
        _str = new String(value, 2, 16);
    }

    public int getIdent() {
        return _ident;
    }

    public String getString() {
        return _str;
    }

    public byte[] getValue() throws IOException {
        byte val[] = new byte[1 + _str.length()];
        byte s[] = _str.getBytes();

        val[0] = (byte) _ident;
        System.arraycopy(s, 0, val, 1, s.length);
        return val;
    }
}
