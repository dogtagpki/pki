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

public class GenerateKeyECCAPDU extends APDU {

    public GenerateKeyECCAPDU(byte theP1, byte theP2, byte alg,
            int keysize, byte option,
            byte type, TPSBuffer wrapped_challenge, TPSBuffer key_check) {

        setCLA((byte) 0x84);
        setINS((byte) 0x0D);
        setP1(theP1);
        setP2(theP2);

        TPSBuffer data1 = new TPSBuffer();

        data1.add(alg);

        data1.add((byte) (keysize / 256));

        data1.add((byte) (keysize % 256));

        data1.add(option);
        data1.add(type);

        data1.add((byte) wrapped_challenge.size());

        data1.add(wrapped_challenge);

        data1.add((byte) key_check.size());

        if (key_check.size() > 0) {
            data1.add(key_check);
        }

        setData(data1);
    }

    @Override
    public APDU.Type getType() {
        return APDU.Type.APDU_GENERATE_KEY_ECC;
    }

}
