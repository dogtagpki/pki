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
import sun.io.ByteToCharUnicodeBig;
import sun.io.ByteToCharUnicodeLittle;
import sun.io.ConversionBufferFullException;
import sun.io.MalformedInputException;

/**
 * Convert byte arrays containing Unicode characters into arrays of actual
 * Unicode characters, sensing the byte order automatically.  To force a
 * particular byte order, use either the "UnicodeBig" or the "UnicodeLittle"
 * encoding.
 *
 * If the first character is a byte order mark, it will be interpreted and
 * discarded. Otherwise, the byte order is assumed to be BigEndian.
 * Either way, the byte order is decided by the first character. Later
 * byte order marks will be passed through as characters (if they indicate
 * the same byte order) or will cause an error (if they indicate the other
 * byte order).
 *
 * @see ByteToCharUnicodeLittle
 * @see ByteToCharUnicodeBig
 *
 * @version 	1.3, 96/11/23
 * @author	Mark Reinhold
 */

public class ByteToCharUnicode extends sun.io.ByteToCharConverter {

    static final char BYTE_ORDER_MARK = (char) 0xfeff;
    static final char REVERSED_MARK = (char) 0xfffe;

    static final int AUTO = 0;
    static final int BIG = 1;
    static final int LITTLE = 2;

    int byteOrder;

    public ByteToCharUnicode() {
	byteOrder = AUTO;
    }

    public String getCharacterEncoding() {
	switch (byteOrder) {
	case BIG:     return "UnicodeBig";
	case LITTLE:  return "UnicodeLittle";
	default:      return "Unicode";
	}
    }

    boolean started = false;
    int leftOverByte;
    boolean leftOver = false;

    public int convert(byte[] in, int inOff, int inEnd,
		       char[] out, int outOff, int outEnd)
	throws ConversionBufferFullException, MalformedInputException
    {
	byteOff = inOff;
	charOff = outOff;

	if (inOff >= inEnd)
	    return 0;

	int b1, b2;
	int bc = 0;
	int inI = inOff, outI = outOff;

	if (leftOver) {
	    b1 = leftOverByte & 0xff;
	    leftOver = false;
	}
	else
	    b1 = in[inI++] & 0xff;
	bc = 1;

	if (!started) {		/* Read possible initial byte-order mark */
	    if (inI < inEnd) {
		b2 = in[inI++] & 0xff;
		bc = 2;

		char c = (char) ((b1 << 8) | b2);
		int bo = AUTO;

		if (c == BYTE_ORDER_MARK)
		    bo = BIG;
		else if (c == REVERSED_MARK)
		    bo = LITTLE;

		if (byteOrder == AUTO) {
		    if (bo == AUTO) {
                        bo = BIG; // BigEndian by default
		    }
		    byteOrder = bo;
		    if (inI < inEnd) {
			b1 = in[inI++] & 0xff;
			bc = 1;
		    }
		}
		else if (bo == AUTO) {
		    inI--;
		    bc = 1;
		}
		else if (byteOrder == bo) {
		    if (inI < inEnd) {
			b1 = in[inI++] & 0xff;
			bc = 1;
		    }
		}
		else {
		    badInputLength = bc;
		    throw new
			MalformedInputException("Incorrect byte-order mark");
		}

		started = true;
	    }
	}

	/* Loop invariant: (b1 contains the next input byte) && (bc == 1) */
	while (inI < inEnd) {
	    b2 = in[inI++] & 0xff;
	    bc = 2;

	    char c;
	    if (byteOrder == BIG)
		c = (char) ((b1 << 8) | b2);
	    else
		c = (char) ((b2 << 8) | b1);

	    if (c == REVERSED_MARK)
		throw new
		    MalformedInputException("Reversed byte-order mark");

	    if (outI >= outEnd)
		throw new ConversionBufferFullException();
	    out[outI++] = c;
	    byteOff = inI;
	    charOff = outI;

	    if (inI < inEnd) {
		b1 = in[inI++] & 0xff;
		bc = 1;
	    }
	}

	if (bc == 1) {
	    leftOverByte = b1;
	    leftOver = true;
	}

	return outI - outOff;
    }

    public void reset() {
	leftOver = false;
	byteOff = charOff = 0;
    }

    public int flush(char buf[], int off, int len)
	throws MalformedInputException
    {
	if (leftOver) {
	    reset();
	    throw new MalformedInputException();
	}
	byteOff = charOff = 0;
	return 0;
    }

}
