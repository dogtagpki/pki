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
package org.dogtagpki.server.tps.apdu;

import org.dogtagpki.server.tps.main.TPSBuffer;

public class Read_Buffer_APDU extends APDU {
    /**
     * Constructs Read Buffer APDU.
     */
    public Read_Buffer_APDU(int len, int offset)
    {
        SetCLA((byte) 0x84);
        SetINS((byte) 0x08);
        SetP1((byte) len);
        SetP2((byte) 0x00);
        TPSBuffer data = new TPSBuffer();

        data.add((byte) (offset / 256));
        data.add((byte) (offset % 256));
        SetData(data);
    }

    public APDU_Type GetType()
    {
        return APDU_Type.APDU_READ_BUFFER;
    }

    public int GetLen()
    {
        return m_p1;
    }

    public int GetOffset()
    {
        byte a = m_data.at(0);
        byte b = m_data.at(1);

        return ((a << 8) + b);
    }

}
