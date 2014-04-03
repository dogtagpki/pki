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
import org.dogtagpki.tps.main.Util;

import com.netscape.certsrv.apps.CMS;

public class APDUResponse extends APDU {

    public APDUResponse() {
        super();

    }

    public APDUResponse(TPSBuffer theData) {
        setData(theData);

    }

    public APDUResponse(APDUResponse cpy) {
        super(cpy);
    }

    public byte getSW1() {
        if (data == null) {
            return 0x0;
        } else {
            if (data.size() < 2) {
                return 0x0;
            } else {
                return data.at(data.size() - 2);
            }
        }

    }

    public byte getSW2() {
        if (data == null) {
            return 0x0;
        } else {
            if (data.size() < 2) {
                return 0x0;
            } else {
                return data.at(data.size() - 1);
            }
        }

    }

    //Not every non 0x90 0x00 is considered fatal, return result
    public boolean checkResult() {
        boolean result = false;

        byte sw1 = getSW1();
        byte sw2 = getSW2();

        int int1 = sw1 & 0xff;
        int int2 = sw2 & 0xff;

        CMS.debug("APDUResponse.checkResult : sw1: " + "0x" + Util.intToHex(int1) + " sw2: " + "0x"
                + Util.intToHex(int2));

        if (sw1 == (byte) 0x90 && sw2 == 0x0)
            result = true;

        return result;
    }

    //Get the two byte apdu return code
    public byte[] getResultCodeBytes() {
        byte[] result = new byte[2];

        result[0] = getSW1();
        result[1] = getSW2();
        return result;
    }

    public TPSBuffer getResultDataNoCode() {

        //Result code will be 2 bytes at the end.
        TPSBuffer theData = getData();

        TPSBuffer result = null;
        int len = theData.size();
        if (len > 2) {
            result = theData.substr(0, len - 2);
        }

        return result;
    }

    public static void main(String args[]) {

        APDUResponse resp = new APDUResponse();
        resp.dump();

    }

}
