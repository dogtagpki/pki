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

public class LifecycleAPDU extends APDU {
    /**
     * Constructs Lifecycle APDU.
     */
    public LifecycleAPDU(byte lifecycle)
    {
        setCLA((byte) 0x84);
        setINS((byte) 0xf0);
        setP1(lifecycle);
        setP2((byte) 0x00);
    }

    @Override
    public Type getType()
    {
        return Type.APDU_LIFECYCLE;
    }

}
