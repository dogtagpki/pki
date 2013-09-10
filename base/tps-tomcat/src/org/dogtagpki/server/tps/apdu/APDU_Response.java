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

public class APDU_Response extends APDU {

    public APDU_Response() {
        super();

    }

    public APDU_Response(TPSBuffer data) {
        super();
        SetData(data);

    }

    public APDU_Response(APDU_Response cpy) {
        super(cpy);
    }

    public byte GetSW1() {
        if (m_data == null) {
            return 0x0;
        } else {
            if (m_data.size() < 2) {
                return 0x0;
            } else {
                return m_data.at(m_data.size() - 2);
            }
        }

    }

    public byte GetSW2() {
        if (m_data == null) {
            return 0x0;
        } else {
            if (m_data.size() < 2) {
                return 0x0;
            } else {
                return m_data.at(m_data.size() - 1);
            }
        }

    }


    public static void main(String args[]) {

        APDU_Response resp = new APDU_Response();
        resp.dump();

    }

}
