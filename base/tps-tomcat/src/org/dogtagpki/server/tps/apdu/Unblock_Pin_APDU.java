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

public class Unblock_Pin_APDU extends APDU {
    /**
     * Constructs Unblock Pin APDU.
     */
    public Unblock_Pin_APDU()
    {
        SetCLA((byte) 0x84);
        SetINS((byte) 0x02);
        SetP1((byte) 0x00);
        SetP2((byte) 0x00);
    }

    public APDU_Type GetType()
    {
        return APDU_Type.APDU_UNBLOCK_PIN;
    }

}
