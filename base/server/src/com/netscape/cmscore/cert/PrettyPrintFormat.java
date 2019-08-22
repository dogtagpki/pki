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
package com.netscape.cmscore.cert;

import com.netscape.certsrv.base.IPrettyPrintFormat;

/**
 * This class will display the certificate content in predefined
 * format.
 *
 * @author Andrew Wnuk
 * @version $Revision$, $Date$
 */
public class PrettyPrintFormat implements IPrettyPrintFormat {

    /*==========================================================
     * variables
     *==========================================================*/
    private String mSeparator = "";
    private int mIndentSize = 0;
    private int mLineLen = 0;

    /*==========================================================
     * constants
     *
     *==========================================================*/
    private final static String spaces =
            "                                                 " +
                    "                                                 " +
                    "                                                 " +
                    "                                                 " +
                    "                                                 ";

    /*==========================================================
     * constructors
     *==========================================================*/

    public PrettyPrintFormat(String separator) {
        mSeparator = separator;
    }

    public PrettyPrintFormat(String separator, int lineLen) {
        mSeparator = separator;
        mLineLen = lineLen;
    }

    public PrettyPrintFormat(String separator, int lineLen, int indentSize) {
        mSeparator = separator;
        mLineLen = lineLen;
        mIndentSize = indentSize;
    }

    /*==========================================================
     * Private methods
     *==========================================================*/

    /*==========================================================
     * public methods
     *==========================================================*/

    /**
     * Provide white space indention
     * stevep - speed improvements. Factor of 10 improvement
     *
     * @param numSpace number of white space to be returned
     * @return white spaces
     */
    public String indent(int size) {
        return spaces.substring(0, size);
    }

    private static final char[] hexdigits = {
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            'A', 'B', 'C', 'D', 'E', 'F'
        };

    /**
     * Convert Byte Array to Hex String Format
     * stevep - speedup by factor of 8
     *
     * @param byte array of data to hexify
     * @param indentSize number of spaces to prepend before each line
     * @param lineLen number of bytes to output on each line (0
     *            means: put everything on one line
     * @param separator the first character of this string will be used as
     *            the separator between bytes.
     * @return string representation
     */

    public String toHexString(byte[] in, int indentSize,
            int lineLen, String separator) {

        if (in == null) return "";

        StringBuffer sb = new StringBuffer(indent(indentSize));
        int hexCount = 0;
        char c[];
        int j = 0;

        if (lineLen == 0) {
            c = new char[in.length * 3 + 1];
        } else {
            c = new char[lineLen * 3 + 1];
        }

        char sep = separator.charAt(0);

        for (int i = 0; i < in.length; i++) {
            if (lineLen > 0 && hexCount == lineLen) {
                c[j++] = '\n';
                sb.append(c, 0, j);
                sb.append(indent(indentSize));
                hexCount = 0;
                j = 0;
            }
            byte x = in[i];

            // output hex digits to buffer
            c[j++] = hexdigits[(char) ((x >> 4) & 0xf)];
            c[j++] = hexdigits[(char) (x & 0xf)];

            // if not last char, output separator
            if (i != in.length - 1) {
                c[j++] = sep;
            }

            hexCount++;
        }
        if (j > 0) {
            c[j++] = '\n';
            sb.append(c, 0, j);
        }
        //        sb.append("\n");

        return sb.toString();
    }

    public String toHexString(byte[] in, int indentSize, int lineLen) {
        return toHexString(in, indentSize, lineLen, mSeparator);
    }

    public String toHexString(byte[] in, int indentSize) {
        return toHexString(in, indentSize, mLineLen);
    }

    public String toHexString(byte[] in) {
        return toHexString(in, mIndentSize);
    }
}
