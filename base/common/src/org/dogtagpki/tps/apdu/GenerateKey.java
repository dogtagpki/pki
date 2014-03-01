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

public class GenerateKey extends APDU {

    public GenerateKey(byte theP1, byte theP2, byte alg,
            int keysize, byte option,
            byte type, TPSBuffer wrapped_challenge, TPSBuffer key_check) {

        SetCLA((byte) 0x84);
        SetINS((byte) 0x0C);
        SetP1(theP1);
        SetP2(theP2);
        data = new TPSBuffer();

        data.add(alg);
        data.add((byte) (keysize / 256));
        data.add((byte) (keysize % 256));

        data.add(option);

        data.add(type);

        data.add((byte) wrapped_challenge.size());
        data.add(wrapped_challenge);

        data.add((byte) key_check.size());

        if (key_check.size() > 0) {
            data.add(key_check);
        }

    }

    public APDU.Type getType() {
        return APDU.Type.APDU_GENERATE_KEY;
    }

}
