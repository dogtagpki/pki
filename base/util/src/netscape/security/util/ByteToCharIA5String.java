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

import sun.io.ByteToCharConverter;
import sun.io.ConversionBufferFullException;
import sun.io.UnknownCharacterException;

/**
 * Converts bytes in ASN.1 IA5String character set to unicode 
 * characters. 
 *
 * @author Lily Hsiao
 * @author Slava Galperin
 */

public class ByteToCharIA5String extends ByteToCharConverter 
{
    public String getCharacterEncoding() {
	return "ASN.1 IA5String";
    }

    public int convert(byte[] input, int inStart, int inEnd,
		       char[] output, int outStart, int outEnd)
	throws ConversionBufferFullException,
		UnknownCharacterException
    {
	int j = outStart;
	for (int i = inStart; i < inEnd; i++, j++) {
	    if (j >= outEnd) {
		byteOff = i;
		charOff = j;
		throw new ConversionBufferFullException();
	    }
	    if (!subMode && (input[i] & 0x80) != 0) {
		byteOff = i;
		charOff = j;
		badInputLength = 1;
		throw new UnknownCharacterException();
	    }
	    output[j] = (char) (input[i] & 0x7f);
	}
	byteOff = inEnd;
	charOff = j;
	return j - outStart;
    }

    public int flush(char[] output, int outStart, int outEnd) {
	return 0;
    }

    public void reset() { }

}
