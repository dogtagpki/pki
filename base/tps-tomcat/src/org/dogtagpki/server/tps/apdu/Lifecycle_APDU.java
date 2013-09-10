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

public class Lifecycle_APDU extends APDU {
    /**
     * Constructs Lifecycle APDU.
     */
    public Lifecycle_APDU(byte lifecycle)
    {
        SetCLA((byte) 0x84);
        SetINS((byte) 0xf0);
        SetP1(lifecycle);
        SetP2((byte) 0x00);
    }

    @Override
    public APDU_Type GetType()
    {
        return APDU_Type.APDU_LIFECYCLE;
    }

}
