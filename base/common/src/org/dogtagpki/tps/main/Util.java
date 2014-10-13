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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;

import netscape.security.x509.AuthorityKeyIdentifierExtension;
import netscape.security.x509.KeyIdentifier;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.SubjectKeyIdentifierExtension;
import netscape.security.x509.X509CertImpl;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.Cipher;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.pkcs11.PK11SymKey;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmsutil.util.Utils;
import com.netscape.symkey.SessionKey;

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

    public static byte bool2Byte(boolean value) {
        if (value)
            return 0x1;
        else
            return 0x0;
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

    public static TPSBuffer computeEncEcbDes(PK11SymKey symKey, TPSBuffer input) throws EBaseException {

        //Asssume 8 bytes message
        if (symKey == null || input == null || input.size() != 8) {
            throw new EBaseException("Util.computeEncEcbDes: invalid input data!");
        }

        CMS.debug("Util.computeEncEcbDes entering... ");

        TPSBuffer result = null;
        CryptoToken token = null;

        int inputLen = input.size();

        TPSBuffer message = new TPSBuffer(input);

        CMS.debug("Util.computeEncEcbDes: input data. " + message.toHexString() + " input len: " + inputLen);

        try {

            token = CryptoManager.getInstance().getInternalKeyStorageToken();

            PK11SymKey des = SessionKey.DeriveDESKeyFrom3DesKey(token.getName(), symKey, 0x00000121 /*CKM_DES_ECB */);

            if (des == null) {
                throw new EBaseException("Util.computeEncEcbDes: Can't derive single des key from triple des key!");
            }

            TPSBuffer desDebug = new TPSBuffer(des.getEncoded());

            CMS.debug("des key debug bytes: " + desDebug.toHexString());

            Cipher cipher = token.getCipherContext(EncryptionAlgorithm.DES_ECB);

            result = new TPSBuffer();

            cipher.initEncrypt(des);
            byte[] ciphResult = cipher.doFinal(message.toBytesArray());

            if (ciphResult.length != 8) {
                throw new EBaseException("Invalid cipher in Util.computeEncEcbDes");
            }

            result.set(ciphResult);

            CMS.debug("Util.computeEncEcbDes: encrypted bloc: " + result.toHexString());

        } catch (Exception e) {
            throw new EBaseException("Util.computeMACdes3des: Cryptographic problem encountered! " + e.toString());
        }

        return result;
    }

    public static TPSBuffer computeMACdes3des(PK11SymKey symKey, TPSBuffer input, TPSBuffer initialIcv)
            throws EBaseException {

        if (symKey == null || input == null || initialIcv == null || initialIcv.size() != 8) {
            throw new EBaseException("Util.coputeMACdes3des: invalid input data!");
        }

        CMS.debug("Util.computeMACdes3des entering... Initial icv: " + initialIcv.toHexString());

        TPSBuffer output = null;
        TPSBuffer mac = null;
        CryptoToken token = null;

        int inputLen = input.size();

        TPSBuffer message = new TPSBuffer(input);
        CMS.debug("Util.computeMACdes3des entering... Input message: " + message.toHexString() + " message.size(): "
                + message.size());

        //Add the padding, looks like we need this even if the remainder is 0
        int remainder = inputLen % 8;

        CMS.debug("Util.computeMACdes3des remainder: " + remainder);

        TPSBuffer macPad = new TPSBuffer(8);
        macPad.setAt(0, (byte) 0x80);

        TPSBuffer padBuff = macPad.substr(0, 8 - remainder);

        message.add(padBuff);
        inputLen += (8 - remainder);

        CMS.debug("Util.computeMACdes3des: padded input data. " + message.toHexString() + " input len: " + inputLen);

        try {

            token = CryptoManager.getInstance().getInternalKeyStorageToken();

            PK11SymKey des = SessionKey.DeriveDESKeyFrom3DesKey(token.getName(), symKey, 0x00000122 /* CKM_DES_CBC */);

            if (des == null) {
                throw new EBaseException("Util.computeMACdes3des: Can't derive single des key from tripe des key!");
            }

            TPSBuffer desDebug = new TPSBuffer(des.getEncoded());

            CMS.debug("des key debug bytes: " + desDebug.toHexString());

            Cipher cipher = token.getCipherContext(EncryptionAlgorithm.DES_CBC);
            Cipher cipher3des = token.getCipherContext(EncryptionAlgorithm.DES3_CBC);
            mac = new TPSBuffer(initialIcv);

            AlgorithmParameterSpec algSpec = new IVParameterSpec(initialIcv.toBytesArray());

            int inputOffset = 0;

            while (inputLen > 8)
            {

                mac.set(message.substr(inputOffset, 8));

                // CMS.debug("About to encrypt1des: " + mac.toHexString());
                cipher.initEncrypt(des, algSpec);
                byte[] ciphResult = cipher.doFinal(mac.toBytesArray());

                if (ciphResult.length != mac.size()) {
                    throw new EBaseException("Invalid cipher in Util.computeMAC");
                }

                mac.set(ciphResult);
                algSpec = new IVParameterSpec(ciphResult);

                // CMS.debug("Util.computeMACdes3des: des encrypted bloc: " + mac.toHexString());

                inputLen -= 8;
                inputOffset += 8;
            }

            // Now do the 3DES portion of the operation

            TPSBuffer newICV = new TPSBuffer(mac);

            CMS.debug("Util.computeMACdes3des: inputOffset: " + inputOffset);

            mac.set(message.substr(inputOffset, 8));

            CMS.debug("About to encrypt 3des: " + mac.toHexString() + " icv: " + newICV.toHexString());

            cipher3des.initEncrypt(symKey, new IVParameterSpec(newICV.toBytesArray()));
            byte[] ciphResultFinal = cipher3des.doFinal(mac.toBytesArray());

            if (ciphResultFinal.length != mac.size()) {
                throw new EBaseException("Invalid cipher in Util.computeMAC");
            }

            output = new TPSBuffer(ciphResultFinal);

            CMS.debug("Util.computeMACdes3des: final mac results: " + output.toHexString());

        } catch (Exception e) {
            throw new EBaseException("Util.computeMACdes3des: Cryptographic problem encountered! " + e.toString());
        }

        return output;
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

        CMS.debug("Util.encryptData: dataToEnc: " + dataToEnc.toHexString());

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

    /*
     * getCertAkiString returns the Authority Key Identifier of the certificate in Base64 encoding
     * @param cert X509CertImpl of the cert to be processed
     * @return Base64 encoding of the cert's AKI
     */
    public static String getCertAkiString(X509CertImpl cert)
            throws EBaseException, IOException {
        if (cert == null) {
            throw new EBaseException("CARemoteRequestHandler: getCertAkiString(): input parameter cert null.");
        }
        AuthorityKeyIdentifierExtension certAKI =
                (AuthorityKeyIdentifierExtension)
                cert.getExtension(PKIXExtensions.AuthorityKey_Id.toString());
        KeyIdentifier kid =
                (KeyIdentifier) certAKI.get(AuthorityKeyIdentifierExtension.KEY_ID);
        return (CMS.BtoA(kid.getIdentifier()).trim());
    }

    /*
     * getCertAkiString returns the Subject Key Identifier of the certificate in Base64 encoding
     * @param cert X509CertImpl of the cert to be processed
     * @return Base64 encoding of the cert's SKI
     */
    public static String getCertSkiString(X509CertImpl cert)
            throws EBaseException, IOException {
        if (cert == null) {
            throw new EBaseException("CARemoteRequestHandler: getCertSkiString(): input parameter cert null.");
        }
        SubjectKeyIdentifierExtension certSKI =
                (SubjectKeyIdentifierExtension)
                cert.getExtension(PKIXExtensions.SubjectKey_Id.toString());
        KeyIdentifier kid =
                (KeyIdentifier) certSKI.get(SubjectKeyIdentifierExtension.KEY_ID);
        return (CMS.BtoA(kid.getIdentifier()).trim());
    }

    /*
     * getTimeStampString() gets current time in string format
     * @param addMicroSeconds true if microseconds wanted in result; false otherwise
     * @return time stamp in String
     */
    public static String getTimeStampString(boolean addMicroSeconds) {
        Calendar c = Calendar.getInstance();
        int year = c.get(Calendar.YEAR);
        int month = c.get(Calendar.MONTH) + 1;
        int day = c.get(Calendar.DAY_OF_MONTH);
        int hour = c.get(Calendar.HOUR_OF_DAY);
        int minute = c.get(Calendar.MINUTE);
        int second = c.get(Calendar.SECOND);

        String timeString = "";
        if (addMicroSeconds) {
            /*
             * TODO: Java does not support microseconds;  Deal with that later
             */
            int microSecond = c.get(Calendar.MILLISECOND) * 1000;

            timeString = String.format(
                    "%04d%02d%02d%02d%02d%02d%06d",
                    year, month, day,
                    hour, minute, second, microSecond);
        } else {
            timeString = String.format(
                    "%04d%02d%02d%02d%02d%02d",
                    year, month, day,
                    hour, minute, second);
        }

        return timeString;
    }

}
