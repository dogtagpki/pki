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

public class List_Pins_APDU extends APDU {

    public List_Pins_APDU(byte ret_size)
    {
        SetCLA((byte) 0xB0);
        SetINS((byte) 0x48);
        SetP1((byte) 0x00);
        SetP2((byte) 0x00);
        m_ret_size = ret_size;
    }

    public APDU_Type GetType()
    {
        return APDU_Type.APDU_LIST_PINS;
    }

    @Override
    public TPSBuffer GetEncoding()
    {
        TPSBuffer data = new TPSBuffer();

        data.add(m_cla);
        data.add(m_ins);
        data.add(m_p1);
        data.add(m_p2);
        data.add(m_ret_size);

        return data;
    } /* Encode */

    private byte m_ret_size = 0;

}
