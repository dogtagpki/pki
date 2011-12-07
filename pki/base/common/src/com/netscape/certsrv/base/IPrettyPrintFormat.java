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
 * This class will display the certificate content in predefined format.
 * 
 * @version $Revision$, $Date$
 */
public interface IPrettyPrintFormat {

    /**
     * Retrieves a pretty print string of the given byte array.
     * 
     * @param in byte array
     * @param indentSize indentation size
     * @param lineLen length of line
     * @param separator separator string
     * @return pretty print string
     */
    public String toHexString(byte[] in, int indentSize, int lineLen,
            String separator);

    /**
     * Retrieves a pretty print string of the given byte array.
     * 
     * @param in byte array
     * @param indentSize indentation size
     * @param lineLen length of line
     * @return pretty print string
     */
    public String toHexString(byte[] in, int indentSize, int lineLen);

    /**
     * Retrieves a pretty print string of the given byte array.
     * 
     * @param in byte array
     * @param indentSize indentation size
     * @return pretty print string
     */
    public String toHexString(byte[] in, int indentSize);

    /**
     * Retrieves a pretty print string of the given byte array.
     * 
     * @param in byte array
     * @return pretty print string
     */
    public String toHexString(byte[] in);
}
