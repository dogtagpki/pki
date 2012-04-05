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

/**
 * Converts characters in ASN.1 UniversalString character set to UniversalString
 * bytes.
 *
 * @author Lily Hsiao
 * @author Slava Galperin
 */

public class UniversalCharsetEncoder extends CharsetEncoder {

    public UniversalCharsetEncoder(Charset cs) {
        super(cs, 4, 4, new byte[] { 0, 0, 0, 0 });
    }

    /*
     * Converts an array of Unicode characters into an array of UniversalString
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

            if (out.remaining() < 4) {
                in.reset();
                return CoderResult.OVERFLOW;
            }

            out.put((byte) 0);
            out.put((byte) 0);
            out.put((byte) ((c >> 8) & 0xff));
            out.put((byte) (c & 0xff));
        }
    }
}
