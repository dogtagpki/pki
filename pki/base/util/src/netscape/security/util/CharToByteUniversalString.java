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
package netscape.security.util;

import sun.io.CharToByteConverter;
import sun.io.ConversionBufferFullException;
import sun.io.UnknownCharacterException;

/**
 * Converts a string of ASN.1 IA5String characters to IA5String bytes.
 * 
 * @author Lily Hsiao
 * @author Slava Galperin
 */

public class CharToByteUniversalString extends CharToByteConverter {
    /*
     * Returns the character set id for the conversion.
     * 
     * @return the character set id.
     */
    public String getCharacterEncoding() {
        return "ASN.1 UniversalString";
    }

    /*
     * Converts an array of Unicode characters into an array of UniversalString
     * bytes and returns the total number of characters converted. If conversion
     * cannot be done, UnknownCharacterException is thrown. The character and
     * byte offset will be set to the point of the unknown character.
     * 
     * @param input character array to convert.
     * 
     * @param inStart offset from which to start the conversion.
     * 
     * @param inEnd where to end the conversion.
     * 
     * @param output byte array to store converted bytes.
     * 
     * @param outStart starting offset in the output byte array.
     * 
     * @param outEnd ending offset in the output byte array.
     * 
     * @return the number of characters converted.
     */
    public int convert(char[] input, int inStart, int inEnd, byte[] output,
            int outStart, int outEnd) throws ConversionBufferFullException,
            UnknownCharacterException {
        int j = outStart;
        for (int i = inStart; i < inEnd; i++) {
            if (j + 3 >= outEnd) {
                charOff = i;
                byteOff = j;
                throw new ConversionBufferFullException();
            }
            output[j++] = 0;
            output[j++] = 0;
            output[j++] = (byte) ((input[i] >> 8) & 0xff);
            output[j++] = (byte) (input[i] & 0xff);
        }

        return j - outStart;
    }

    public int flush(byte[] output, int outStart, int outEnd) {
        return 0;
    }

    public void reset() {
    }

    public int getMaxBytesPerChar() {
        return 4;
    }
}
