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

public class ReadObject extends APDU {
    /**
     * Constructs Read Object APDU.
     *
     * ReadObject APDU format:
     * CLA 0x84
     * INS 0x56
     * P1 0x00
     * P2 0x00
     * lc 0x09
     * DATA <Data Parameters>
     *
     * [DATA] Parameters are:
     * Long Object ID;
     * Long Offset
     * Byte Data Size;
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

    public ReadObject(byte[] object_id, int offset, int len)
    {
        SetCLA((byte) 0x84);
        SetINS((byte) 0x56);
        SetP1((byte) 0x00);
        SetP2((byte) 0x00);
        data = new TPSBuffer();

        data.add(object_id[0]);
        data.add(object_id[1]);
        data.add(object_id[2]);
        data.add(object_id[3]);

        data.add((byte) ((offset >> 24) & 0xff));
        data.add((byte) ((offset >> 16) & 0xff));
        data.add((byte) ((offset >> 8) & 0xff));
        data.add((byte) (offset & 0xff));
        data.add((byte) len);
    }

    @Override
    public Type getType()
    {
        return Type.APDU_READ_OBJECT;
    }

}
