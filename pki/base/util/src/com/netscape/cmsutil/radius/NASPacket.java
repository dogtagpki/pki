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

public abstract class NASPacket extends Packet {
    public NASPacket(int c, short id, Authenticator auth) {
        super(c, id, auth);
    }

    public byte[] getData() throws IOException {
        // prepare the attributes first
        ByteArrayOutputStream attrsOS = new ByteArrayOutputStream();

        for (int i = 0; i < _attrs.size(); i++) {
            Attribute attr = (Attribute) getAttributeAt(i);

            attrsOS.write(attr.getData());
        }
        byte attrsData[] = attrsOS.toByteArray();

        ByteArrayOutputStream dataOS = new ByteArrayOutputStream();

        dataOS.write(_c); // code
        dataOS.write(_id); // identifier
        int len = attrsData.length + 20;

        dataOS.write((len >>> 8) & 0xFF);
        dataOS.write(len & 0xFF);
        dataOS.write(_auth.getData());
        dataOS.write(attrsData);

        return dataOS.toByteArray();
    }
}
