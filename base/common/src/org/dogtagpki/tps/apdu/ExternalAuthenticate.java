// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.tps.apdu;

import org.dogtagpki.server.tps.channel.SecureChannel;
import org.dogtagpki.tps.main.TPSBuffer;

public class ExternalAuthenticate extends APDU {

    public ExternalAuthenticate(TPSBuffer theData, SecureChannel.SecurityLevel sl) {

        SetCLA((byte) 0x84);
        SetINS((byte) 0x82);
        SetP1((byte) 0x01);

        if (sl == SecureChannel.SecurityLevel.SECURE_MSG_MAC_ENC) {
            SetP1((byte) 0x03);
        } else if (sl == SecureChannel.SecurityLevel.SECURE_MSG_NONE) {
            SetP1((byte) 0x00);
        } else { // default
            SetP1((byte) 0x01);
        }

        SetP2((byte) 0x00);
        SetData(theData);
    }

    public TPSBuffer GetHostCryptogram()
    {
        return getData();
    }

    @Override
    public APDU.Type getType()
    {
        return APDU.Type.APDU_EXTERNAL_AUTHENTICATE;
    }

    public static void main(String[] args) {
        // TODO Auto-generated method stub

    }

}
