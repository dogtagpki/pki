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

public class Initialize_Update_APDU extends APDU {

    /**
     * Constructs Initialize Update APDU.
     */
    public Initialize_Update_APDU(byte key_version, byte key_index, TPSBuffer data)
    {
        SetCLA((byte) 0x80);
        SetINS((byte) 0x50);
        SetP1(key_version);
        SetP2(key_index);
        SetData(data);
    }

    public TPSBuffer GetHostChallenge()
    {
        return GetData();
    }

    public APDU_Type GetType()
    {
        return APDU_Type.APDU_INITIALIZE_UPDATE;
    }

    public TPSBuffer GetEncoding()
    {
        TPSBuffer data = new TPSBuffer();

        data.add(m_cla);
        data.add(m_ins);
        data.add(m_p1);
        data.add(m_p2);
        data.add((byte) m_data.size());
        data.add(m_data);

        return data;
    } /* Encode */

}
