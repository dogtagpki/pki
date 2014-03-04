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

public class CreateObject extends APDU {
    /**
     * Constructs a Create Object APDU. This APDU is usually sent right
     * before Write_Buffer_APDU is sent. This APDU only creates an Object
     * on token, but does not actually writes object content until
     * Write_Buffer_APDU is sent.
     *
     * CreateObject APDU format:
     * CLA 0x84
     * INS 0x5a
     * P1 0x00
     * P2 0x00
     * lc 0x0e
     * DATA <Object Parameters>
     *
     * [DATA] Object Parameters are:
     * Long Object ID;
     * Long Object Size;
     * ObjectACL ObjectACL;
     *
     * Connection requirement:
     * Secure Channel
     *
     * Possible error Status Codes:
     * 9C 06 - unauthorized
     * 9C 08 - object already exists
     * 9C 01 - insufficient memory on card to complete the operation
     *
     * NOTE:
     * Observe that the PIN identity is hard-coded at n.2 for each
     * permission. In Housekey, this is probably a non-issue, however,
     * in housekey, do we not allow multiple people (presumably closely
     * -related) to share one token with individual certs? We should
     * consider exposing this as an input param.
     *
     * @param object_id as defined in APDU
     * @param len length of object
     * @see APDU
     */

    public CreateObject(byte[] object_id, byte[] permissions, int len) {

        if (object_id.length != 4)
            return;

        if (permissions.length != 6)
            return;

        setCLA((byte) 0x84);
        setINS((byte) 0x5a);
        setP1((byte) 0x00);
        setP2((byte) 0x00);

        data = new TPSBuffer();

        data.add((object_id[0]));
        data.add((object_id[1]));
        data.add((object_id[2]));
        data.add((object_id[3]));

        data.add((byte) (len >> 24));
        data.add((byte) ((len >> 16) & 0xff));
        data.add((byte) ((len >> 8) & 0xff));
        data.add((byte) (len & 0xff));

        data.add(permissions[0]);
        data.add(permissions[1]);
        data.add(permissions[2]);
        data.add(permissions[3]);
        data.add(permissions[4]);
        data.add(permissions[5]);

    }

    @Override
    public APDU.Type getType() {
        return APDU.Type.APDU_CREATE_OBJECT;

    }

    public static void main(String args[]) {

        byte[] object_id = { 0x01, 0x02, 0x3, 0x4 };
        byte[] permisisons = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x6 };

        CreateObject apdu = new CreateObject(object_id, permisisons, 56);

        if (apdu != null) {

            apdu.dump();
        }

    }

}
