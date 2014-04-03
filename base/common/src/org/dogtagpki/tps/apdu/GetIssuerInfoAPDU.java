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

public class GetIssuerInfoAPDU extends APDU {
    /**
     * Constructs GetIssuer APDU.
     *
     * SecureGetIssuer APDU format:
     * CLA 0x84
     * INS 0xF6
     * P1 0x00
     * P2 0x00
     * lc 0xE0
     * DATA <Issuer Info>
     *
     * Connection requirement:
     * Secure Channel
     *
     * Possible error Status Codes:
     * 9C 06 - unauthorized
     *
     * @param p1 always 0x00
     * @param p2 always 0x00
     * @param data issuer info
     * @see APDU
     */
    public GetIssuerInfoAPDU()
    {
        setCLA((byte) 0x84);
        setINS((byte) 0xF6);
        setP1((byte) 0x00);
        setP2((byte) 0x00);
    }

    @Override
    public APDU.Type getType()
    {
        return Type.APDU_GET_ISSUERINFO;
    }

    @Override
    public TPSBuffer getEncoding()
    {
        TPSBuffer encoding = new TPSBuffer();

        encoding.add(cla);
        encoding.add(ins);
        encoding.add(p1);
        encoding.add(p2);
        encoding.add((byte) 0xe0);

        return encoding;
    } /* Encode */

}
