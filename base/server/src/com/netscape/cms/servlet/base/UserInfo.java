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
package com.netscape.cms.servlet.base;

/**
 * This class represents information about the client e.g. version,
 * langauge, vendor.
 *
 * @version $Revision$, $Date$
 */
public class UserInfo {
    public final static String MSIE = "MSIE";
    public final static String MOZILLA = "Mozilla";

    /**
     * Constructs a user information object.
     */
    public UserInfo() {
    }

    /**
     * Returns the user language.
     *
     * @param s user language info from the browser
     * @return user language
     */
    public static String getUserLanguage(String s) {
        // Does this contain a country code?
        int pos = s.indexOf("-");

        if (pos != -1) {
            // Yes it does
            return s.substring(0, pos);
        }
        return s;
    }

    /**
     * Returns the user country.
     *
     * @param s user language info from the browser
     * @return user country
     */
    public static String getUserCountry(String s) {
        // Does this contain a country code?
        int pos = s.indexOf("-");

        if (pos != -1) {
            // Yes it does
            return s.substring(pos + 1);
        }
        return "";
    }

    /**
     * Returns the users agent.
     *
     * @param s user language info from the browser
     * @return user agent
     */
    public static String getUserAgent(String s) {
        // Check for MSIE
        if (s.indexOf(MSIE) != -1) {
            return MSIE;
        }

        // Check for Netscape i.e. Mozilla
        if (s.indexOf(MOZILLA) != -1) {
            return MOZILLA;
        }

        // Don't know agent. Return empty string.
        return "";
    }
}
