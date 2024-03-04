/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/

package com.netscape.management.client.util;

import java.util.*;
import java.io.*;

/**
 * Encode a byte array in URL format. This class augments java.net.URLEncode class
 * and provides method encode(byte[] s). The method is required for URL encoding of
 * UTF8 characters, which are non ascii. A typical usage would be
 *
 * try {
 *     String url = URLByteEncoder.encode(myString.getBytes("UTF8"));
 * }
 * catch (Exception e) {
 * }
 *
 * Becase most of the output strings will be converted to UTF8, a utility method
 * encodeUTF8(String s) is provided. The same effect as in the previous usage exmaple
 * can be achived with
 *
 * String url = URLByteEncode.encodeUTF8(myString);
 *
 * We can not subclass java.net.URLEncoder as its static data memebrs have only local
 * package visisbility. Thus, the code here is a modification of the java.net.URLEncoder
 */

public class URLByteEncoder {

    protected static BitSet dontNeedEncoding;
    protected static final int caseDiff = ('a' - 'A');

    /* The list of characters that are not encoded have been determined by
       referencing O'Reilly's "HTML: The Definitive Guide" (page 164). */

    static {
        dontNeedEncoding = new BitSet(256);
        int i;
        for (i = 'a'; i <= 'z'; i++) {
            dontNeedEncoding.set(i);
        }
        for (i = 'A'; i <= 'Z'; i++) {
            dontNeedEncoding.set(i);
        }
        for (i = '0'; i <= '9'; i++) {
            dontNeedEncoding.set(i);
        }
        dontNeedEncoding.set(' '); /* encoding a space to a + is done in the encode() method */
        dontNeedEncoding.set('-');
        dontNeedEncoding.set('_');
        dontNeedEncoding.set('.');
        dontNeedEncoding.set('*');
    }


    /**
      * Convert a string to UTF8 byte array
      */
    public static byte[] toUTF8Format(String str) {
        try {
            return str.getBytes("UTF8");
        } catch (Exception e) {
            // This should never happen, UTF8 is a standard encodings supported by JDK1.1
            Debug.println(0, "ERROR: Can not construct String with UTF8 encoding");
            return new byte[0];
        }
    }


    /**
      * Encode a string in UTF8 and URL format
      */

    public static String encodeUTF8(String s) {
        return encode(toUTF8Format(s));
    }

    /**
      * Encode a byte array in YRL format
      */
    public static String encode(byte[] s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length);

        for (int i = 0; i < s.length; i++) {
            int c = (int) s[i];
            if (c < 0)
                c += 256;
            if (dontNeedEncoding.get(c)) {
                if (c == ' ') {
                    c = '+';
                }
                out.write(c);
            } else {

                out.write('%');
                char ch = Character.forDigit((c >> 4) & 0xF, 16);
                // converting to use uppercase letter as part of
                // the hex value if ch is a letter.
                if (Character.isLetter(ch)) {
                    ch -= caseDiff;
                }
                out.write(ch);

                ch = Character.forDigit(c & 0xF, 16);
                if (Character.isLetter(ch)) {
                    ch -= caseDiff;
                }
                out.write(ch);
            }
        }

        return out.toString();
    }

}

