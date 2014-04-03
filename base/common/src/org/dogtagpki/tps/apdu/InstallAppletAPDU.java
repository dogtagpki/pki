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

public class InstallAppletAPDU extends APDU {

    public InstallAppletAPDU(TPSBuffer packageAID, TPSBuffer appletAID,
            byte appPrivileges, int instanceSize, int appletMemorySize)
    {
        setCLA((byte) 0x84);
        setINS((byte) 0xE6);
        setP1((byte) 0x0C);
        setP2((byte) 0x00);

        data = new TPSBuffer();
        data.add((byte) packageAID.size());
        data.add(packageAID);
        data.add((byte) appletAID.size());
        data.add(appletAID);
        data.add((byte) appletAID.size());
        data.add(appletAID);

        data.add((byte) 0x01); // length of application privileges byte
        data.add(appPrivileges);

        TPSBuffer installParams = new TPSBuffer();
        installParams.add((byte) 0xEF);
        installParams.add((byte) 0x04);
        installParams.add((byte) 0xC8);
        installParams.add((byte) 0x02);

        installParams.add((byte) ((instanceSize >> 8) & 0xff));
        installParams.add((byte) (instanceSize & 0xff));
        installParams.add((byte) 0xC9);

        //Now add some applet specific init data that the applet supports
        //Length of applet specific data

        installParams.add((byte) 0x04);

        //Issuer info length.
        //Leave this to zero since TPS already writes phone home info to card.
        installParams.add((byte) 0x00);

        //Length of applet memory size
        installParams.add((byte) 0x02);

        // Applet memory block size

        installParams.add((byte) ((appletMemorySize >> 8) & 0xff));
        installParams.add((byte) (appletMemorySize & 0xff));

        data.add((byte) installParams.size());
        data.add(installParams);
        data.add((byte) 0x00); // size of token return data
    }

    /**
     * Constructs Install Applet APDU.
     */
    public InstallAppletAPDU(TPSBuffer theData)
    {
        setCLA((byte) 0x84);
        setINS((byte) 0xE6);
        setP1((byte) 0x0C);
        setP2((byte) 0x00);
        setData(theData);
    }

    @Override
    public Type getType()
    {
        return Type.APDU_INSTALL_APPLET;
    }

}
