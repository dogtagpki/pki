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
package com.netscape.certsrv.common;

import java.util.LinkedHashMap;
import java.util.StringTokenizer;

/**
 * A class represents an ordered list of name
 * value pairs.
 *
 * @version $Revision$, $Date$
 */
public class NameValuePairs extends LinkedHashMap<String, String> {

    private static final long serialVersionUID = 1494507857048437440L;

    /**
     * Constructs name value pairs.
     */
    public NameValuePairs() {
    }

    /**
     * Show the content of this name value container as
     * string representation.
     *
     * @return string representation
     */
    public String toString() {
        StringBuffer buf = new StringBuffer();

        for (String name : keySet()) {
            String value = get(name);

            buf.append(name + "=" + value);
            buf.append("\n");
        }

        return buf.toString();
    }

    /**
     * Parses a string into name value pairs.
     *
     * @param s string
     * @param nvp name value pairs
     * @return true if successful
     */
    public static boolean parseInto(String s, NameValuePairs nvp) {
        StringTokenizer st = new StringTokenizer(s, "&");

        while (st.hasMoreTokens()) {
            String t = st.nextToken();
            int i = t.indexOf("=");

            if (i == -1) {
                return false;
            }
            String n = t.substring(0, i);
            String v = t.substring(i + 1);

            nvp.put(n, v);
        }
        return true;
    }
}
