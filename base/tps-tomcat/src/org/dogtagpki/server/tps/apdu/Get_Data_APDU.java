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

public class Get_Data_APDU extends APDU {

    public Get_Data_APDU ()
    {
        SetCLA((byte)0x80);
        SetINS((byte)0xCA);
        SetP1((byte)0x9F);
        SetP2((byte)0x7F);
    }

    @Override
    public APDU_Type GetType()
    {
            return APDU.APDU_Type.APDU_GET_DATA;
    }

    @Override
    public TPSBuffer GetEncoding()
    {
        TPSBuffer data = new TPSBuffer();

        data.add(m_cla);
        data.add(m_ins);
        data.add( m_p1);
        data.add(m_p2);
        data.add((byte)0x2D);

        return data;
    } /* Encode */

    public static void main(String[] args) {
        Get_Data_APDU get_data = new Get_Data_APDU();

        get_data.dump();

    }
}
