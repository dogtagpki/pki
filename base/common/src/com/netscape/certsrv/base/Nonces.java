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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.base;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * This class provides a limited storage for nonces. Usually
 * nonces are added and removed immediately. In case some of
 * the nonces are abandoned, the oldest nonce will be removed
 * if the storage size grows exceeding the limit.
 *
 * @version $Revision$, $Date$
 */
public class Nonces extends LinkedHashMap<Object,Long> {

    private static final long serialVersionUID = 7953840029228765259L;

    private int limit;

    public Nonces() {
        this(100);
    }

    public Nonces(int limit) {
        this.limit = limit;
    }

    /**
     * Override removeEldestEntry() to remove eldest entry
     * if the size exceeds the limit.
     */
    protected boolean removeEldestEntry(Map.Entry<Object,Long> eldest) {
        return size() > limit;
    }

    public static void main(String[] args) {
        Nonces nonces = new Nonces(3);

        System.out.println("Adding 3 entries.");
        nonces.put("a", 1l);
        nonces.put("b", 2l);
        nonces.put("c", 3l);

        System.out.println("Nonces:");
        for (Object id : nonces.keySet()) {
            System.out.println(" - "+id+": "+nonces.get(id));
        }

        System.out.println("Adding 2 more entries.");
        nonces.put("d", 4l);
        nonces.put("e", 5l);

        System.out.println("Nonces:");
        for (Object id : nonces.keySet()) {
            System.out.println(" - "+id+": "+nonces.get(id));
        }
    }
}
