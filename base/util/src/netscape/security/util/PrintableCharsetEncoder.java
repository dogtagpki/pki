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

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;

/**
 * Converts characters in ASN.1 PrintableString character set to PrintableString
 * bytes.
 * 
 * @author Lily Hsiao
 * @author Slava Galperin
 */

public class PrintableCharsetEncoder extends CharsetEncoder {

    public PrintableCharsetEncoder(Charset cs) {
        super(cs, 1, 1);
    }

    /*
     * Converts an array of Unicode characters into an array of PrintableString
     * bytes and returns the conversion result.
     * @param in input character buffer to convert.
     * @param out byte buffer to store output.
     * @return encoding result.
     */
    protected CoderResult encodeLoop(CharBuffer in, ByteBuffer out) {

        while (true) {

            if (in.remaining() < 1)
                return CoderResult.UNDERFLOW;

            in.mark();
            char c = in.get();

            if (CodingErrorAction.REPORT == unmappableCharacterAction() &&
                    !PrintableCharset.isPrintableChar(c)) {
                return CoderResult.unmappableForLength(1);
            }

            if (out.remaining() < 1) {
                in.reset();
                return CoderResult.OVERFLOW;
            }

            out.put((byte) (c & 0x7f));
        }
    }
}
