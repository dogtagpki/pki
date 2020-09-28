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

import org.dogtagpki.tps.main.TPSBuffer;

public class ExternalAuthenticateAPDU extends APDU {

    public enum SecurityLevel {
        SECURE_MSG_ANY,
        SECURE_MSG_MAC,
        SECURE_MSG_NONE, // not yet supported
        SECURE_MSG_MAC_ENC,

    }

    public ExternalAuthenticateAPDU(TPSBuffer theData, SecurityLevel securityLevel) {
        setCLA((byte) 0x84);
        setINS((byte) 0x82);

        setP1(securityLevelToByte(securityLevel));
        setP2((byte) 0x0);

        setData(theData);
    }

    public TPSBuffer getHostCryptogram()
    {
        return getData();
    }

    @Override
    public APDU.Type getType()
    {
        return APDU.Type.APDU_EXTERNAL_AUTHENTICATE;
    }

    public static byte securityLevelToByte(SecurityLevel level) {
        byte result = 0;

        switch (level) {
        case SECURE_MSG_ANY:
            result = 0;
            break;
        case SECURE_MSG_MAC:
            result = 1;
            break;
        case SECURE_MSG_NONE:
            result = 2;
            break;
        case SECURE_MSG_MAC_ENC:
            result = 3;
            break;

        default:
            result = 0;
            break;

        }

        return result;
    }

    public static SecurityLevel byteToSecurityLevel(byte level) {

        SecurityLevel result = SecurityLevel.SECURE_MSG_ANY;

        switch (level) {

        case 0:
            result = SecurityLevel.SECURE_MSG_ANY;
            break;
        case 1:
            result = SecurityLevel.SECURE_MSG_MAC;
            break;
        case 2:
            result = SecurityLevel.SECURE_MSG_NONE;
            break;
        case 3:
            result = SecurityLevel.SECURE_MSG_MAC_ENC;
            break;
        default:
            result = SecurityLevel.SECURE_MSG_ANY;
            break;
        }

        return result;
    }

    public static void main(String[] args) {
        // TODO Auto-generated method stub

    }

}
