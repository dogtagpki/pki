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
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;

/**
 * Converts bytes in ASN.1 UniversalString character set to UniversalString
 * characters.
 *
 * @author Lily Hsiao
 * @author Slava Galperin
 */

public class UniversalCharsetDecoder extends CharsetDecoder {

    public UniversalCharsetDecoder(Charset cs) {
        super(cs, 0.25f, 1);
    }

    protected CoderResult decodeLoop(ByteBuffer in, CharBuffer out) {

        while (true) {
            // XXX we do not know what to do with truly UCS-4 characters here
            // we also assumed network byte order

            if (in.remaining() < 4) return CoderResult.UNDERFLOW;

            in.mark();
            byte b0 = in.get();
            byte b1 = in.get();
            byte b2 = in.get();
            byte b3 = in.get();

            if (CodingErrorAction.REPORT == unmappableCharacterAction() &&
                !((b0 == 0 && b1 == 0) || (b2 == 0 && b3 == 0))) {
                return CoderResult.unmappableForLength(4);
            }

            char c;
            if (b2 == 0 && b3 == 0) {
                // Try to be a bit forgiving. If the byte order is
                // reversed, we still try handle it.

                // Sample Date Set (1):
                // 0000000   f   0  \0  \0 213   0  \0  \0   S   0  \0  \0
                // 0000014

                // Sample Date Set (2):
                // 0000000   w  \0  \0  \0   w  \0  \0  \0   w  \0  \0  \0   .  \0  \0  \0
                // 0000020   (  \0  \0  \0   t  \0  \0  \0   o  \0  \0  \0   b  \0  \0  \0
                // 0000040   e  \0  \0  \0   |  \0  \0  \0   n  \0  \0  \0   o  \0  \0  \0
                // 0000060   t  \0  \0  \0   t  \0  \0  \0   o  \0  \0  \0   b  \0  \0  \0
                // 0000100   e  \0  \0  \0   )  \0  \0  \0   .  \0  \0  \0   c  \0  \0  \0
                // 0000120   o  \0  \0  \0   m  \0  \0  \0
                // 0000130
                c = (char)(((b1 << 8) & 0xff00) + (b0 & 0x00ff));

            } else { // (b0 == 0 && b1 == 0)
                // This should be the right order.
                //
                // 0000000 0000 00c4 0000 0064 0000 006d 0000 0069
                // 0000020 0000 006e 0000 0020 0000 0051 0000 0041
                // 0000040

                c = (char)(((b2 << 8) & 0xff00) + (b3 & 0x00ff));
            }

            if (out.remaining() < 1) {
                in.reset();
                return CoderResult.OVERFLOW;
            }

            out.put(c);
        }
    }
}
