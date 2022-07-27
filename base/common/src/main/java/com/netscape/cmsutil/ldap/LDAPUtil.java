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
package com.netscape.cmsutil.ldap;

import netscape.ldap.LDAPControl;

public class LDAPUtil {

    // special chars are *, (, ), \, null
    public static String SPECIAL_CHARS = "*()\\\000";

    /**
     * This method escapes special characters for LDAP filter (RFC 4515).
     * Each special character will be replaced by a backslash followed by
     * 2-digit hex of the ASCII code.
     *
     * @param object string to escape
     * @return escaped string
     */
    public static String escapeFilter(Object object) {
        StringBuilder sb = new StringBuilder();
        for (char c : object.toString().toCharArray()) {
            if (SPECIAL_CHARS.indexOf(c) >= 0) {
                sb.append('\\');
                if (c < 0x10)
                    sb.append('0'); // make sure it's 2-digit
                sb.append(Integer.toHexString(c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * This method escapes special characters for LDAP DN (RFC 1779).
     */
    public static String escapeRDNValue(Object value) {
        return LDAPUtil.escapeRDNValue(value.toString(), false);
    }

    public static String escapeRDNValue(String value, boolean doubleEscape) {
        StringBuilder sb = new StringBuilder();

        // Do we need to escape any characters
        for (int i = 0; i < value.length(); i++) {
            int c = value.charAt(i);
            if (c == ',' || c == '=' || c == '+' || c == '<' ||
                    c == '>' || c == '#' || c == ';' || c == '\r' ||
                    c == '\n' || c == '\\' || c == '"') {
                if ((c == 0x5c) && ((i + 1) < value.length())) {
                    int nextC = value.charAt(i + 1);
                    if ((c == 0x5c) && (nextC == ',' || nextC == '=' || nextC == '+' ||
                            nextC == '<' || nextC == '>' || nextC == '#' ||
                            nextC == ';' || nextC == '\r' || nextC == '\n' ||
                            nextC == '\\' || nextC == '"')) {
                        if (doubleEscape)
                            sb.append('\\');
                    } else {
                        sb.append('\\');
                        if (doubleEscape)
                            sb.append('\\');
                    }
                } else {
                    sb.append('\\');
                    if (doubleEscape)
                        sb.append('\\');
                }
            }
            if (c == '\r') {
                sb.append("0D");
            } else if (c == '\n') {
                sb.append("0A");
            } else {
                sb.append((char) c);
            }
        }
        return sb.toString();
    }

    /**
     * Get the control of the specified class from the array of controls.
     *
     * @return the LDAPControl, or null if not found
     */
    public static LDAPControl getControl(
            Class<? extends LDAPControl> cls, LDAPControl[] controls) {
        if (controls != null) {
            for (LDAPControl control : controls) {
                if (cls.isInstance(control))
                    return control;
            }
        }
        return null;
    }
}
