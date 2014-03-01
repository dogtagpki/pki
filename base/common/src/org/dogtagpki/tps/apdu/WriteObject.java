/* --- BEGIN COPYRIGHT BLOCK ---
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA
 *
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 */
package org.dogtagpki.tps.apdu;

import org.dogtagpki.tps.main.TPSBuffer;

public class WriteObject extends APDU {
    /**
     * Constructs Write Buffer APDU. This APDU is usually sent right after
     * the Create_Object_APDU is sent. This APDU writes the actual object
     * content into the object that was created with Create_Object_APDU.
     * This APDU is used for both write and re-writes of data.
     * The object data is stored starting from the byte specified by the
     * offset parameter.
     * Up to 240 bytes can be transferred with a single APDU. If more bytes
     * need to be transferred, then multiple WriteObject commands must be
     * used with different offsets.
     *
     * WriteObject APDU format:
     * CLA 0x84
     * INS 0x54
     * P1 0x00
     * P2 0x00
     * lc Data Size + 9
     * DATA <Data Parameters>
     *
     * [DATA] Parameters are:
     * Long Object ID;
     * Long Offset
     * Byte Data Size;
     * Byte[] Object Data
     *
     * Connection requirement:
     * Secure Channel
     *
     * Possible error Status Codes:
     * 9C 06 - unauthorized
     * 9C 07 - object not found
     *
     * @param object_id as defined in APDU
     * @param offset
     * @param data
     * @see APDU
     */
    public WriteObject(byte[] object_id, int offset, TPSBuffer data)
    {
        if (object_id.length != 4) {
            return;
        }

        SetCLA((byte) 0x84);
        SetINS((byte) 0x54);
        SetP1((byte) 0x00);
        SetP2((byte) 0x00);

        TPSBuffer data1 = new TPSBuffer();

        data1.add(object_id[0]);
        data1.add(object_id[1]);

        data1.add(object_id[2]);
        data1.add(object_id[3]);

        data1.add((byte) ((offset >> 24) & 0xff));
        data1.add((byte) ((offset >> 16) & 0xff));
        data1.add((byte) ((offset >> 8) & 0xff));
        data1.add((byte) (offset & 0xff));
        data1.add((byte) data.size());
        data1.add(data);
        SetData(data1);
    }

    public Type getType()
    {
        return Type.APDU_WRITE_OBJECT;
    }

}
