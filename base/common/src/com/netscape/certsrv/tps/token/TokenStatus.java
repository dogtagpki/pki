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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.tps.token;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Endi S. Dewata
 */
public enum TokenStatus {

    UNINITIALIZED(0),
    DAMAGED(1),
    PERM_LOST(2),
    TEMP_LOST(3),
    ACTIVE(4),
    TEMP_LOST_PERM_LOST(5),
    TERMINATED(6);

    static Map<Integer, TokenStatus> map = new HashMap<Integer, TokenStatus>();

    Integer value;

    static {
        for (TokenStatus state : TokenStatus.values()) {
            map.put(state.value, state);
        }
    }

    TokenStatus(Integer value) {
        this.value = value;
    }

    public static TokenStatus fromInt(Integer value) {
        return map.get(value);
    }

    public int toInt() {
        return value.intValue();
    }
}
