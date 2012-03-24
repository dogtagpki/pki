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
package netscape.security.x509;

/**
 * This class is used to parse attribute names like "x509.info.extensions".
 * 
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.4
 */
public class X509AttributeName {
    // Public members
    private static final char SEPARATOR = '.';

    // Private data members
    private String prefix = null;
    private String suffix = null;

    /**
     * Default constructor for the class. Name is of the form
     * "x509.info.extensions".
     * 
     * @param name the attribute name.
     */
    public X509AttributeName(String name) {
        int i = name.indexOf(SEPARATOR);
        if (i == (-1)) {
            prefix = name;
        } else {
            prefix = name.substring(0, i);
            suffix = name.substring(i + 1);
        }
    }

    /**
     * Return the prefix of the name.
     */
    public String getPrefix() {
        return (prefix);
    }

    /**
     * Return the suffix of the name.
     */
    public String getSuffix() {
        return (suffix);
    }
}
