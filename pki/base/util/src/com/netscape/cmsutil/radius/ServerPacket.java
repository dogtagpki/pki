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


public abstract class ServerPacket extends Packet {
    public ServerPacket(byte data[]) throws IOException {
        super();
        _c = data[0];
        _id = data[1];
        int datalen = data[3] & 0xFF;

        datalen |= ((data[2] << 8) & 0xFF00);
        byte authData[] = new byte[16];

        System.arraycopy(data, 4, authData, 0, 16);
        _auth = new ResponseAuthenticator(authData);

        // building attributes
        int startp = 20;

        while (startp != datalen) {
            int attrLen = (data[startp + 1] & 0xFF);
            byte attrData[] = new byte[attrLen];

            System.arraycopy(data, startp, attrData, 0, attrData.length); 
            addAttribute(AttributeFactory.createAttribute(attrData));	
            startp += attrData.length;
        }
    }
}
