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


/**
 * AttributeNameHelper. This Helper class used to decompose 
 * dot-separated attribute name into prefix and suffix.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class AttributeNameHelper {
    // Public members
    private static final char SEPARATOR = '.';
	
    // Private data members
    private String prefix = null;
    private String suffix = null;
	
    /**
     * Default constructor for the class. Name is of the form
     * "proofOfPosession.type".
     *
     * @param name the attribute name.
     */
    public AttributeNameHelper(String name) {
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
     *
     * @return attribute prefix
     */
    public String getPrefix() {
        return (prefix);
    }
	
    /**
     * Return the suffix of the name.
     *
     * @return attribute suffix
     */
    public String getSuffix() {
        return (suffix);
    }
}

