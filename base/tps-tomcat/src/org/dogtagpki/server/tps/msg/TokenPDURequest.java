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
package org.dogtagpki.server.tps.msg;

import org.dogtagpki.server.tps.apdu.APDU;
import org.dogtagpki.server.tps.apdu.Select_APDU;
import org.dogtagpki.server.tps.main.TPSBuffer;
import org.dogtagpki.server.tps.main.Util;

public class TokenPDURequest extends TPSMessage {

    public TokenPDURequest(APDU apdu) {

        put(MSG_TYPE_NAME, msgTypeToInt(Msg_Type.MSG_TOKEN_PDU_REQUEST));

        if(apdu != null) {

            TPSBuffer encoding = apdu.GetEncoding();
            int apduSize = encoding.size();

            String apdu_value = Util.URIEncodeInHex(encoding.toBytesArray());

            put(PDU_SIZE_NAME,apduSize);
            put(PDU_DATA_NAME,apdu_value);

        }

    }

    public static void main(String[] args) {

        Select_APDU apdu = null;

        byte[] select_aid = { (byte) 0xa0, 0x0, 0x0, 0x0, 0x3, 0x0 , 0x0 };

        TPSBuffer select = new TPSBuffer(select_aid, select_aid.length);

        apdu = new Select_APDU((byte) 0x4,(byte) 0x0, select);

        TokenPDURequest  request = new TokenPDURequest(apdu);

        System.out.println(request.encode());

     }

}
