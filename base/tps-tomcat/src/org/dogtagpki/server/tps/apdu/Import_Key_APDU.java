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

public class Import_Key_APDU extends APDU {
    /**
     * Constructs Import Key APDU.
     *
     * CLA 0x84
     * INS 0x32
     * P1 Key Number (0x00 -0x0F) - key slot number defined in CS.cfg
     * P2 0x00
     * P3 Import Parameters Length (6 bytes: 3 shorts if just for ACL)
     * DATA Import Parameters
     *
     * This function allows th eimport of a key into the card by (over)-writing the Cardlet memory.  Object ID 0xFFFFFFFE needs to be initialized with a key blob before invocation of this function so tha tit can retrieve the key from this object. The exact key blob contents depend on th ekey's algorithm, type and actual import parameters.  The key's number, algorithm type, and parameters are specified by argumetns P1, P2, P3, and DATA.  Appropriate values for these are specified below:

    [DATA]
    Import Parameters:
    KeyACL ACL for the imported key;
    Byte[] Additional parameters; // Optional
    If KeyBlob's Encoding is BLOB_ENC_PLAIN(0x00), there are no additional parameters.
     */
    public Import_Key_APDU (byte p1)
    {
        SetCLA((byte)0x84);
        SetINS((byte)0x32);
        SetP1(p1);
        SetP2((byte)0x00);
        //    SetP3(p3);

        TPSBuffer data = new TPSBuffer();
        data.add((byte) 0xFF);

        data.add((byte) 0xFF);
        data.add((byte) 0x40); // means "write" allowed for RA only
        data.add((byte) 0x00);
        data.add((byte) 0xFF) ;// means "use" allowed for everyone
        data.add((byte) 0xFF);

        SetData(data);
    }

    @Override
    public APDU_Type GetType()
    {
            return APDU_Type.APDU_IMPORT_KEY;
    }


}
