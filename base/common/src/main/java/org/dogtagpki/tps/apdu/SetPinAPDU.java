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

public class SetPinAPDU extends APDU {
    /**
     * Constructs SetPin APDU.
     *
     * SecureSetPIN APDU format:
     * CLA 0x80
     * INS 0x04
     * P1 <Pin number>
     * P2 0x00
     * lc <data length>
     * DATA <New Pin Value>
     *
     * Connection requirement:
     * Secure Channel
     *
     * Possible error Status Codes:
     * 9C 06 - unauthorized
     *
     * @param p1 Pin number: 0x00 - 0x07
     * @param p2 always 0x00
     * @param data pin
     * @see APDU
     */
    public SetPinAPDU(byte p1, byte p2, TPSBuffer data)
    {
        setCLA((byte) 0x84);
        setINS((byte) 0x04);
        setP1(p1);
        setP2(p2);
        setData(data);
    }

    public TPSBuffer getNewPIN()
    {
        return getData();
    }

    @Override
    public Type getType()
    {
        return Type.APDU_SET_PIN;
    }

}
