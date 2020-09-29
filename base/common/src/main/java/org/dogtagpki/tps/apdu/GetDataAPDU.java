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

public class GetDataAPDU extends APDU {

    public GetDataAPDU()
    {
        setCLA((byte) 0x80);
        setINS((byte) 0xCA);
        setP1((byte) 0x9F);
        setP2((byte) 0x7F);
    }

    public GetDataAPDU(byte[] identifier) {

        this();

        if(identifier != null && identifier.length == 2) {
            setP1(identifier[0]);
            setP2(identifier[1]);
        }

    }

    @Override
    public Type getType()
    {
        return APDU.Type.APDU_GET_DATA;
    }

    @Override
    public TPSBuffer getEncoding()
    {
        TPSBuffer encoding = new TPSBuffer();

        encoding.add(cla);
        encoding.add(ins);
        encoding.add(p1);
        encoding.add(p2);
        encoding.add((byte) 0x2D);

        return encoding;
    } /* Encode */

    public static void main(String[] args) {
        GetDataAPDU get_data = new GetDataAPDU();

        get_data.dump();

    }
}
