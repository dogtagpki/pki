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

public class InstallLoadAPDU extends APDU {

    public InstallLoadAPDU(TPSBuffer packageAID, TPSBuffer sdAID,
            int fileLen)
    {

        setCLA((byte) 0x84);
        setINS((byte) 0xE6);
        setP1((byte) 0x02);
        setP2((byte) 0x00);

        TPSBuffer inputData = new TPSBuffer();
        inputData.add((byte) packageAID.size());
        inputData.add(packageAID);
        inputData.add((byte) sdAID.size());
        inputData.add(sdAID);
        inputData.add((byte) 0x0);
        inputData.add((byte) 0x6);
        inputData.add((byte) 0xEF);
        inputData.add((byte) 0x04);
        inputData.add((byte) 0xC6);
        inputData.add((byte) 0x02);
        fileLen += 24 + sdAID.size();
        inputData.add((byte) ((fileLen >> 8) & 0xff));
        inputData.add((byte) (fileLen & 0xff));

        setData(inputData);
    }

    /**
     * Constructs Install Load APDU. Used when data was pre-constructed
     */
    public InstallLoadAPDU(TPSBuffer theData)
    {
        setCLA((byte) 0x84);
        setINS((byte) 0xE6);
        setP1((byte) 0x02);
        setP2((byte) 0x00);
        setData(theData);
    }

    @Override
    public Type getType()
    {
        return Type.APDU_INSTALL_LOAD;
    }

}
