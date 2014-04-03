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
import java.security.spec.AlgorithmParameterSpec;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.Cipher;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.pkcs11.PK11SymKey;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmsutil.util.Utils;

public class Util {

    public Util() {
    }

    public static byte[] str2ByteArray(String s) {
        int len = s.length() / 2;

        byte[] ret = new byte[len];

        for (int i = 0; i < len; i++) {
            ret[i] = (byte) ((byte) Util.hexToBin(s.charAt(i * 2)) * 16 + Util.hexToBin(s.charAt(i * 2 + 1)));
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

    public static String specialURLEncode(TPSBuffer data) {
        return specialURLEncode(data.toBytesArray());
    }

    public static String specialURLEncode(byte data[]) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < data.length; i++) {
            sb.append("#");
            if ((data[i] & 0xff) < 16) {
                sb.append("0");
            }
            sb.append(Integer.toHexString((data[i] & 0xff)));
        }

        return sb.toString().toUpperCase();
    }

    public static String specialEncode(TPSBuffer data) {
        return Utils.SpecialEncode(data.toBytesArray());
    }


    public static TPSBuffer computeMAC(PK11SymKey symKey, TPSBuffer input, TPSBuffer icv) throws EBaseException {
        TPSBuffer output = null;
        TPSBuffer result = null;

        int inputLen = input.size();

        if (symKey == null || input == null || icv == null || icv.size() != 8) {
            throw new EBaseException("Util.computeMAC: invalid input data!");
        }

        TPSBuffer macPad = new TPSBuffer(8);
        macPad.setAt(0, (byte) 0x80);

        CryptoToken token = null;

        try {

            token = CryptoManager.getInstance().getInternalKeyStorageToken();

            Cipher cipher = token.getCipherContext(EncryptionAlgorithm.DES3_ECB);
            result = new TPSBuffer(icv);

            /* Process whole blocks */
            int inputOffset = 0;
            while (inputLen >= 8)
            {
                for (int i = 0; i < 8; i++)
                {
                    //Xor implicitly converts bytes to ints, we convert answer back to byte.
                    byte a = (byte) (result.at(i) ^ input.at(inputOffset + i));
                    result.setAt(i, a);
                }
                cipher.initEncrypt(symKey);
                byte[] ciphResult = cipher.doFinal(result.toBytesArray());

                if (ciphResult.length != result.size()) {
                    throw new EBaseException("Invalid cipher in Util.computeMAC");
                }

                result = new TPSBuffer(ciphResult);

                inputLen -= 8;
                inputOffset += 8;
            }

            /*
             * Fold in remaining data (if any)
             * Set i to number of bytes processed
             */
            int i = 0;
            for (i = 0; i < inputLen; i++)
            {
                byte a = (byte) (result.at(i) ^ input.at(i + inputOffset));
                result.setAt(i, a);
            }

            /*
             * Fill remainder of last block. There
             * will be at least one byte handled here.
             */

            //Start at the beginning of macPad
            // Keep going with i in result where we left off.
            int padOffset = 0;
            while (i < 8)
            {
                byte a = (byte) (result.at(i) ^ macPad.at(padOffset++));
                result.setAt(i, a);
                i++;
            }

            cipher.initEncrypt(symKey);
            byte[] ciphResultFinal = cipher.doFinal(result.toBytesArray());

            if (ciphResultFinal.length != result.size()) {
                throw new EBaseException("Invalid cipher in Util.computeMAC");
            }

            output = new TPSBuffer(ciphResultFinal);

        } catch (Exception e) {
            throw new EBaseException("Util.computeMAC: Cryptographic problem encountered! " + e.toString());
        }

        return output;
    }

    public static TPSBuffer specialDecode(String str) {
        byte[] data = uriDecodeFromHex(str);
        TPSBuffer tbuf = new TPSBuffer(data);
        return tbuf;
    }

    public static TPSBuffer encryptData(TPSBuffer dataToEnc, PK11SymKey encKey) throws EBaseException {

        TPSBuffer encrypted = null;
        if (encKey == null || dataToEnc == null) {
            throw new EBaseException("Util.encryptData: called with no sym key or no data!");
        }

        CryptoToken token = null;
        try {

            token = CryptoManager.getInstance().getInternalKeyStorageToken();
            Cipher cipher = token.getCipherContext(EncryptionAlgorithm.DES3_CBC);

            AlgorithmParameterSpec algSpec = null;

            int len = EncryptionAlgorithm.DES3_CBC.getIVLength();
            byte[] iv = new byte[len]; // Assume iv set to 0's as in current TPS

            algSpec = new IVParameterSpec(iv);
            cipher.initEncrypt(encKey, algSpec);

            byte[] encryptedBytes = cipher.doFinal(dataToEnc.toBytesArray());

            encrypted = new TPSBuffer(encryptedBytes);

        } catch (Exception e) {
            throw new EBaseException("Util.encryptData: problem encrypting data: " + e.toString());
        }

        return encrypted;

    }

}
