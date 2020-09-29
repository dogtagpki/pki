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

public class InitializeUpdateAPDU extends APDU {

    /**
     * Constructs Initialize Update APDU.
     */
    public InitializeUpdateAPDU(byte key_version, byte key_index, TPSBuffer theData) {
        setCLA((byte) 0x80);
        setINS((byte) 0x50);
        setP1(key_version);
        setP2(key_index);
        setData(theData);
    }

    public TPSBuffer getHostChallenge()
    {
        return getData();
    }

    public Type getType()
    {
        return Type.APDU_INITIALIZE_UPDATE;
    }

    public TPSBuffer getEncoding()
    {
        TPSBuffer theData = new TPSBuffer();

        theData.add(cla);
        theData.add(ins);
        theData.add(p1);
        theData.add(p2);
        theData.add((byte) data.size());
        theData.add(data);

        return theData;
    } /* Encode */

}
