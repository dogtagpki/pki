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
package org.dogtagpki.tps.msg;

import org.dogtagpki.tps.apdu.APDUResponse;
import org.dogtagpki.tps.main.TPSBuffer;
import org.dogtagpki.tps.main.Util;

public class TokenPDUResponse extends TPSMessage {
    public TokenPDUResponse(String message) {

        super(message);
        response = null;

        String size = get(PDU_SIZE_NAME);
        String apduData = get(PDU_DATA_NAME);

        int sizeI = Integer.parseInt(size);

        byte[] decoded_pdu_data = Util.URIDecodeFromHex(apduData);

        if (decoded_pdu_data.length == sizeI) {

            TPSBuffer responseBuffer = new TPSBuffer(decoded_pdu_data);

            response = new APDUResponse(responseBuffer);

        }

    }

    private APDUResponse response;

    public APDUResponse getResponseAPDU() {
        return response;
    }

    public static void main(String[] args) {

        String pdu_data = "s=46&msg_type=10&pdu_size=6&pdu_data=R%B3F%85%90%00";
        TokenPDUResponse msg = new TokenPDUResponse(pdu_data);

        System.out.println(msg.encode());

        String pdu_data1 = "s=38&msg_type=10&pdu_size=2&pdu_data=%90%00";
        TokenPDUResponse msg1 = new TokenPDUResponse(pdu_data1);

        System.out.println(msg1.encode());

    }

}
