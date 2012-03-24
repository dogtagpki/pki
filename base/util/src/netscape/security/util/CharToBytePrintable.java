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
import sun.io.MalformedInputException;

/**
 * Converts a string of ASN.1 PrintableString characters to PrintableString 
 * bytes.
 *
 * @author Lily Hsiao
 * @author Slava Galperin
 */

public class CharToBytePrintable extends CharToByteConverter
{
    /*
     * returns the character set id for the conversion.
     * @return the character set id.
     */
    public String getCharacterEncoding()
    {
	return "ASN.1 Printable";
    }

    public static boolean isPrintableChar( char c ) 
    {
	if ((c < 'A' || c > 'Z') &&
	    (c < 'a' || c > 'z') && 
	    (c < '0' || c > '9') && 
	    (c != ' ') && 
	    (c != '\'') && 
	    (c != '(') && 
	    (c != ')') && 
	    (c != '+') && 
	    (c != ',') && 
	    (c != '-') && 
	    (c != '.') && 
	    (c != '/') && 
	    (c != ':') && 
	    (c != '=') && 
	    (c != '?')) 
	{
	    return false;
	} else {
	    return true;
	}
    }

    /* 
     * Converts an array of Unicode characters into an array of Printable
     * String bytes and returns the total number of characters converted.
     * If conversion cannot be done, UnknownCharacterException is
     * thrown. The character and byte offset will be set to the point
     * of the unknown character. 
     * @param input character array to convert.
     * @param inStart offset from which to start the conversion.
     * @param inEnd where to end the conversion.
     * @param output byte array to store converted bytes.
     * @param outStart starting offset in the output byte array.
     * @param outEnd ending offset in the output byte array.
     * @return the number of characters converted.
     */
    public int convert(char[] input, int inStart, int inEnd, 
			byte[] output, int outStart, int outEnd)
	throws MalformedInputException, UnknownCharacterException,
		ConversionBufferFullException
    {
 	int j = outStart;
	int i;
	for (i = inStart; i < inEnd ; i++, j++) 
	{
	    if (j >= outEnd) {
		charOff = i;
		byteOff = j;
		throw new ConversionBufferFullException();
	    }
	    if (!subMode && !isPrintableChar(input[i])) {
		charOff = i;
		byteOff = j;
		badInputLength = 1;
		throw new UnknownCharacterException();
	    }
	    output[j] = (byte) (input[i] & 0x7f);
	}
	charOff = i;
	byteOff = j;
	return j - outStart;
    }

    public int flush(byte[] output, int outStart, int outEnd)
	throws MalformedInputException, ConversionBufferFullException
    {
	return 0;
    }

    public void reset() { }

    public int getMaxBytesPerChar()
    {
	return 1;
    }

}
