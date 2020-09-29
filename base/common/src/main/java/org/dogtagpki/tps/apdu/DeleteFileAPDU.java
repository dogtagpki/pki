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

public class DeleteFileAPDU extends APDU {

    public DeleteFileAPDU(TPSBuffer aid) {
        setCLA((byte) 0x84);
        setINS((byte) 0xE4);
        setP1((byte) 0x00);
        setP2((byte) 0x00);

        TPSBuffer AIDTLV = new TPSBuffer();

        AIDTLV.add((byte) 0x4f);
        AIDTLV.add((byte) aid.size());

        AIDTLV.add(aid);

        setData(AIDTLV);

    }

    @Override
    public APDU.Type getType() {
        return APDU.Type.APDU_DELETE_FILE;

    }

    public static void main(String[] args) {
        // TODO Auto-generated method stub

    }

}
