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

public class CreatePinAPDU  extends APDU {

    public  CreatePinAPDU(byte theP1, byte theP2, TPSBuffer theData) {

        setCLA((byte) 0x84);
        setINS((byte) 0x40);
        setP1(theP1);
        setP2(theP2);
        setData(theData);

    }

    @Override
    public APDU.Type getType() {
        return APDU.Type.APDU_CREATE_PIN;

    }

    public static void main(String[] args) {
        // TODO Auto-generated method stub

    }

}
