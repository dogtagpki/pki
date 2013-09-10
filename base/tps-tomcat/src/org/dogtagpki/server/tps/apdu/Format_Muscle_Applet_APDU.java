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

/* Not sure this is used , provide stub right now. */

public class Format_Muscle_Applet_APDU  extends APDU {
    public Format_Muscle_Applet_APDU(short memSize,
            TPSBuffer PIN0, byte pin0Tries,
            TPSBuffer unblockPIN0, byte unblock0Tries,
            TPSBuffer PIN1, byte pin1Tries,
            TPSBuffer unblockPIN1, byte unblock1Tries,
            short objCreationPermissions,
            short keyCreationPermissions,
            short pinCreationPermissions) {

        SetCLA((byte) 0xB0);
        SetINS((byte)0x2A);
        SetP1((byte)0x00);
        SetP2((byte)0x00);

        SetData(null);
    }


    @Override
    public APDU.APDU_Type GetType() {
        return APDU.APDU_Type.APDU_FORMAT_MUSCLE_APPLET;
    }

    @Override
    public TPSBuffer GetEncoding() {
        return super.GetEncoding();

    }
}
