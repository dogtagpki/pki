/* --- BEGIN COPYRIGHT BLOCK ---
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA
 *
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 */
package org.dogtagpki.tps.main;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;


public class Util {

    public Util() {
    }

    public static byte[]  str2ByteArray (String s)  {
        int len = s.length() / 2;


        byte[]  ret = new byte[len];

        for (int i = 0; i < len; i ++) {
               ret[i] =  (byte) ((byte) Util.hexToBin(s.charAt(i*2)) * 16 +  Util.hexToBin(s.charAt(i*2+1)));
        }

        return ret;
    }

    public static int hexToBin(char ch) {
        if ('0' <= ch && ch <= '9')
            return ch - '0';
        if ('A' <= ch && ch <= 'F')
            return ch - 'A' + 10;
        if ('a' <= ch && ch <= 'f')
            return ch - 'a' + 10;
        return -1;
    }

    public static String intToHex(int val) {

        return Integer.toHexString(val);
    }

    public static void main(String[] args) {
        // TODO Auto-generated method stub

    }

    public static String uriDecode(String encoded) throws UnsupportedEncodingException {

        return URLDecoder.decode(encoded, "UTF-8");
    }

    public static String uriEncode(String decoded) throws UnsupportedEncodingException {

        return URLEncoder.encode(decoded, "UTF-8");
    }

    public static byte[] uriDecodeFromHex(String buff) {

        byte[] result = null;
        byte[] tmp = null;

        int i;

        int len = buff.length();
        int sum = 0;

        if (len == 0)
            return null;

        tmp = new byte[len];

        for (i = 0; i < len; i++) {
            if (buff.charAt(i) == '+') {
                tmp[sum++] = ' ';
            } else if (buff.charAt(i) == '%') {
                tmp[sum++] = (byte) ((hexToBin(buff.charAt(i + 1)) << 4) + hexToBin(buff.charAt(i + 2)));
                i += 2;
            } else {
                tmp[sum++] = (byte) buff.charAt(i);
            }
        }

        result = new byte[sum];

        System.arraycopy(tmp, 0, result, 0, sum);

        return result;
    }

    public static String uriEncodeInHex(byte[] buff) {

        final String HEX_DIGITS = "0123456789ABCDEF";

        StringBuffer result = new StringBuffer(buff.length * 2);

        for (int i = 0; i < buff.length; i++)
        {
            char c = (char) buff[i];

            result.append('%');
            result.append(HEX_DIGITS.charAt((c & 0xF0) >> 4));
            result.append(HEX_DIGITS.charAt(c & 0x0F));

        }

        return result.toString();
    }

}
