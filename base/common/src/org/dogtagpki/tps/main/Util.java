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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Calendar;

import netscape.security.x509.AuthorityKeyIdentifierExtension;
import netscape.security.x509.KeyIdentifier;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.SubjectKeyIdentifierExtension;
import netscape.security.x509.X509CertImpl;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.BadPaddingException;
import org.mozilla.jss.crypto.Cipher;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.IllegalBlockSizeException;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.pkcs11.PK11SymKey;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmsutil.util.Utils;
import com.netscape.symkey.SessionKey;

public class Util {

    //SCP03 AES-CMAC related constants
    private static final byte AES_CMAC_CONSTANT = (byte) 0x87;
    private static final int AES_CMAC_BLOCK_SIZE = 16;

    public static final byte CARD_CRYPTO_KDF_CONSTANT_SCP03 = 0x0;
    public static final byte HOST_CRYPTO_KDF_CONSTANT_SCP03 = 0x1;

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

    //Use AES-CMAC (SCP03, counter method) to calculate cryptogram, constant determines whether it is a card or host cryptogram
    public static TPSBuffer compute_AES_CMAC_Cryptogram(SymmetricKey symKey, TPSBuffer context, byte kdfConstant)
             throws EBaseException {

        String method = "Util compute_AES_Crypto:";
        // 11 bytes label
        byte[] label = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        // sanity checking

        if (symKey == null || context == null ) {
            throw new EBaseException(method + " Invalid input!");
        }

        TPSBuffer data = new TPSBuffer();
        int outputBits = 8 * 8;

        //output size of cmac PRF
        final int h = 128;

        int remainder = outputBits % h;

        //calculate counter size
        int n = 0;
        if (remainder == 0) {
            n = outputBits / h;
        } else {
            n = outputBits / h + 1;
        }

        byte b1 = (byte) ((outputBits >> 8) & 0xFF);
        byte b2 = (byte) (outputBits & 0xFF);

        TPSBuffer outputBitsBinary = new TPSBuffer(2);
        outputBitsBinary.setAt(0, b1);
        outputBitsBinary.setAt(1, b2);

        data.addBytes(label);
        data.add(kdfConstant);
        data.add((byte) 0x0);
        data.add(outputBitsBinary);

        TPSBuffer output = new TPSBuffer();
        TPSBuffer input = new TPSBuffer();

        TPSBuffer kI = null;

        for (int i = 1; i <= n; i++) {
            input.add(data);
            input.add((byte) i);
            input.add(context);

            kI = Util.computeAES_CMAC(symKey, input);

            output.add(kI);
        }

        return output.substr(0,8);
    }

    // Implements agorithm http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38b.pdf
    // Input an aes key of 128, 192, or 256 bits

    public static TPSBuffer computeAES_CMAC(SymmetricKey aesKey, TPSBuffer input) throws EBaseException {

        String method = "Util.computeAES_CMAC:";
        byte iv[] = null;

        if (aesKey == null || input == null) {
            throw new EBaseException(method + " invalid input data!");
        }

        TPSBuffer data = new TPSBuffer(input);

        String alg = aesKey.getAlgorithm();
        System.out.println(" AES ALG: " + alg);

        EncryptionAlgorithm eAlg = EncryptionAlgorithm.AES_128_CBC;
        int ivLength = eAlg.getIVLength();

        if (ivLength > 0) {
            iv = new byte[ivLength];
        }

        if (!("AES".equals(alg))) {
            throw new EBaseException(method + " invalid in put key type , must be AES!");
        }

        byte[] k0 = new byte[AES_CMAC_BLOCK_SIZE];

        //Encrypt the zero array
        CryptoToken token = aesKey.getOwningToken();
        Cipher encryptor = null;

        try {
            encryptor = token.getCipherContext(EncryptionAlgorithm.AES_128_CBC);
            encryptor.initEncrypt(aesKey, new IVParameterSpec(iv));
            k0 = encryptor.doFinal(k0);

        } catch (NoSuchAlgorithmException | TokenException | IllegalStateException | IllegalBlockSizeException
                | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new EBaseException(e);
        }

        byte[] k1 = getAES_CMAC_SubKey(k0);
        byte[] k2 = getAES_CMAC_SubKey(k1);

        int numBlocks = 0;
        int messageSize = data.size();
        boolean perfectBlocks = false;

        if (((messageSize % AES_CMAC_BLOCK_SIZE) == 0) && (messageSize != 0)) {
            numBlocks = messageSize / AES_CMAC_BLOCK_SIZE;
            perfectBlocks = true;
        }
        else {
            numBlocks = messageSize / AES_CMAC_BLOCK_SIZE + 1;
            perfectBlocks = false;
        }

        int index = 0;
        byte inb = 0;
        if (perfectBlocks == true)
        {
            // If the size of the message is an integer multiple of the block  block size (namely, 128 bits) (16 bytes)
            // the last block shall be exclusive-OR'ed with the first subKey k1

            for (int j = 0; j < k1.length; j++) {
                index = messageSize - AES_CMAC_BLOCK_SIZE + j;
                inb = data.at(index);
                data.setAt(index, (byte) (inb ^ k1[j]));
            }
        }
        else
        {
            // Otherwise, the last block shall be padded with 10^i
            TPSBuffer padding = new TPSBuffer(AES_CMAC_BLOCK_SIZE - messageSize % AES_CMAC_BLOCK_SIZE);
            padding.setAt(0, (byte) 0x80);

            data.add(padding);
            //Get new data size , it's changed
            messageSize = data.size();

            // and exclusive-OR'ed with K2
            for (int j = 0; j < k2.length; j++) {
                index = messageSize - AES_CMAC_BLOCK_SIZE + j;
                inb = data.at(index);
                data.setAt(index, (byte) (inb ^ k2[j]));
            }
        }

        // Initialization vector starts as zeroes but changes inside the loop's
        // subsequent iterations, it becomes the last encryption output
        byte[] encData = new byte[AES_CMAC_BLOCK_SIZE];
        TPSBuffer currentBlock = null;

        for (int i = 0; i < numBlocks; i++) {
            try {
                encryptor.initEncrypt(aesKey, new IVParameterSpec(encData));
                currentBlock = data.substr(i * AES_CMAC_BLOCK_SIZE, AES_CMAC_BLOCK_SIZE);
                encData = encryptor.doFinal(currentBlock.toBytesArray());
            } catch (TokenException | IllegalStateException | IllegalBlockSizeException
                    | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
                throw new EBaseException(e);
            }
        }

        TPSBuffer aesMacData = new TPSBuffer(encData);
        return aesMacData;

    }

    //Support method for AES-CMAC alg (SCP03).
    private static byte[] getAES_CMAC_SubKey(byte[] input) {

        byte[] output = new byte[input.length];

        boolean msbSet = ((input[0]&0x80) != 0);
        for (int i=0; i<input.length; i++) {
            output[i] = (byte) (input[i] << 1);
            if (i+1 < input.length && ((input[i+1]&0x80) != 0)) {
                output[i] |= 0x01;
            }
        }
        if (msbSet) {
            output[output.length-1] ^= AES_CMAC_CONSTANT;
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

    //Encrypt data with aes. Supports 128 for now.
    public static TPSBuffer encryptDataAES(TPSBuffer dataToEnc, PK11SymKey encKey,TPSBuffer iv) throws EBaseException {

        TPSBuffer encrypted = null;
        if (encKey == null || dataToEnc == null) {
            throw new EBaseException("Util.encryptDataAES: called with no sym key or no data!");
        }

        CryptoToken token = null;


        try {
            token = CryptoManager.getInstance().getInternalKeyStorageToken();
            Cipher cipher = token.getCipherContext(EncryptionAlgorithm.AES_128_CBC);
            AlgorithmParameterSpec algSpec = null;
            int len = EncryptionAlgorithm.AES_128_CBC.getIVLength();

            byte[] ivEnc = null;
            if(iv == null) { //create one
                ivEnc = new byte[len];
            } else {
                ivEnc = iv.toBytesArray();
             }

            algSpec = new IVParameterSpec(ivEnc);
            cipher.initEncrypt(encKey, algSpec);
            byte[] encryptedBytes = cipher.doFinal(dataToEnc.toBytesArray());
            encrypted = new TPSBuffer(encryptedBytes);

        } catch (Exception e) {
            throw new EBaseException("Util.encryptDataAES: problem encrypting data: " + e.toString());
        }

        return encrypted;

    }

    public static TPSBuffer encryptData(TPSBuffer dataToEnc, PK11SymKey encKey) throws EBaseException {

        TPSBuffer encrypted = null;
        if (encKey == null || dataToEnc == null) {
            throw new EBaseException("Util.encryptData: called with no sym key or no data!");
        }

        //CMS.debug("Util.encryptData: dataToEnc: " + dataToEnc.toHexString());

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

    //AES CMAC test samples
    public static void main(String[] args) {

   /*     Options options = new Options();

        options.addOption("d", true, "Directory for tokendb");

        String db_dir = null;
        CryptoManager cm = null;

        // 128 bit aes test key
        byte devKey[] = { (byte) 0x2b, (byte) 0x7e, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xae, (byte) 0xd2,
                (byte) 0xa6, (byte) 0xab, (byte) 0xf7, (byte) 0x15, (byte) 0x88, (byte) 0x09, (byte) 0xcf, (byte) 0x4f,
                (byte) 0x3c };

        // 192 bit aes test key
        byte devKey192[] = { (byte) 0x8e, (byte) 0x73, (byte) 0xb0, (byte) 0xf7, (byte) 0xda, (byte) 0x0e, (byte) 0x64,
                (byte) 0x52,
                (byte) 0xc8, (byte) 0x10, (byte) 0xf3, (byte) 0x2b, (byte) 0x80, (byte) 0x90, (byte) 0x79, (byte) 0xe5,
                (byte) 0x62, (byte) 0xf8, (byte) 0xea, (byte) 0xd2, (byte) 0x52, (byte) 0x2c, (byte) 0x6b, (byte) 0x7b
        };

        byte devKey256[] = { (byte) 0x60, (byte) 0x3d, (byte) 0xeb, (byte) 0x10, (byte) 0x15, (byte) 0xca, (byte) 0x71,
                (byte) 0xbe,
                (byte) 0x2b, (byte) 0x73, (byte) 0xae, (byte) 0xf0, (byte) 0x85, (byte) 0x7d, (byte) 0x77, (byte) 0x81,
                (byte) 0x1f, (byte) 0x35, (byte) 0x2c, (byte) 0x07, (byte) 0x3b, (byte) 0x61, (byte) 0x08, (byte) 0xd7,
                (byte) 0x2d,
                (byte) 0x98, (byte) 0x10, (byte) 0xa3, (byte) 0x09, (byte) 0x14, (byte) 0xdf, (byte) 0xf4

        };

        byte message[] = { (byte) 0x6b, (byte) 0xc1, (byte) 0xbe, (byte) 0xe2, (byte) 0x2e, (byte) 0x40, (byte) 0x9f,
                (byte) 0x96, (byte) 0xe9, (byte) 0x3d, (byte) 0x7e, (byte) 0x11,
                (byte) 0x73, (byte) 0x93, (byte) 0x17, (byte) 0x2a };

        byte message320[] = { (byte) 0x6b, (byte) 0xc1, (byte) 0xbe, (byte) 0xe2, (byte) 0x2e, (byte) 0x40,
                (byte) 0x9f, (byte) 0x96, (byte) 0xe9,
                (byte) 0x3d, (byte) 0x7e, (byte) 0x11, (byte) 0x73, (byte) 0x93, (byte) 0x17, (byte) 0x2a,
                (byte) 0xae, (byte) 0x2d, (byte) 0x8a, (byte) 0x57, (byte) 0x1e, (byte) 0x03, (byte) 0xac, (byte) 0x9c,
                (byte) 0x9e, (byte) 0xb7,
                (byte) 0x6f, (byte) 0xac, (byte) 0x45, (byte) 0xaf, (byte) 0x8e, (byte) 0x51,
                (byte) 0x30, (byte) 0xc8, (byte) 0x1c, (byte) 0x46, (byte) 0xa3, (byte) 0x5c, (byte) 0xe4, (byte) 0x11 };

        byte message512[] = { (byte) 0x6b, (byte) 0xc1, (byte) 0xbe, (byte) 0xe2, (byte) 0x2e, (byte) 0x40,
                (byte) 0x9f, (byte) 0x96, (byte) 0xe9, (byte) 0x3d,
                (byte) 0x7e, (byte) 0x11, (byte) 0x73, (byte) 0x93, (byte) 0x17, (byte) 0x2a,
                (byte) 0xae, (byte) 0x2d, (byte) 0x8a, (byte) 0x57, (byte) 0x1e, (byte) 0x03, (byte) 0xac, (byte) 0x9c,
                (byte) 0x9e, (byte) 0xb7, (byte) 0x6f,
                (byte) 0xac, (byte) 0x45, (byte) 0xaf, (byte) 0x8e, (byte) 0x51,
                (byte) 0x30, (byte) 0xc8, (byte) 0x1c, (byte) 0x46, (byte) 0xa3, (byte) 0x5c, (byte) 0xe4, (byte) 0x11,
                (byte) 0xe5, (byte) 0xfb, (byte) 0xc1,
                (byte) 0x19, (byte) 0x1a, (byte) 0x0a, (byte) 0x52, (byte) 0xef,
                (byte) 0xf6, (byte) 0x9f, (byte) 0x24, (byte) 0x45, (byte) 0xdf, (byte) 0x4f, (byte) 0x9b, (byte) 0x17,
                (byte) 0xad, (byte) 0x2b, (byte) 0x41,
                (byte) 0x7b, (byte) 0xe6, (byte) 0x6c, (byte) 0x37, (byte) 0x10

        };


        byte message_test1[] = { 0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x04,0x0,0x0,(byte) 0x80,0x01,
                (byte)0xd0,(byte)0x61,(byte) 0xff,(byte)0xf4,(byte)0xd8,(byte)0x2f,(byte)0xdf,
                (byte)0x87,(byte)0x5a,(byte)0x5c,(byte)0x90,(byte)0x99,(byte)0x98,(byte)0x3b,(byte)0x24,(byte)0xdc };

        byte devKey_test1[] = {(byte)0x88,(byte)0xc6,(byte)0x46,(byte)0x2e,(byte)0x55,(byte)0x58,(byte)0x6c,
                (byte)0x47,(byte)0xf9,(byte)0xff,0x00,(byte)0x92,(byte)0x39,(byte)0xce,(byte)0xb6,(byte)0xea};

        //Test keys and messages found here: http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38b.pdf
        //Results computed in this test program can be compared against those in the preceding document.

        try {
            CommandLineParser parser = new DefaultParser();
            CommandLine cmd = parser.parse(options, args);

            if (cmd.hasOption("d")) {
                db_dir = cmd.getOptionValue("d");
            }

        } catch (ParseException e) {
            System.err.println("Error in parsing command line options: " + e.getMessage());

        }

        SymmetricKey aes128 = null;
        SymmetricKey aes192 = null;
        SymmetricKey aes256 = null;

        SymmetricKey tempKey = null;

        // Initialize token
        try {
            CryptoManager.initialize(db_dir);
            cm = CryptoManager.getInstance();

            CryptoToken token = cm.getInternalKeyStorageToken();

            // Generate temp key with only function is to
            // unwrap the various test keys onto the token

            KeyGenerator kg = token.getKeyGenerator(KeyGenAlgorithm.AES);

            SymmetricKey.Usage usages[] = new SymmetricKey.Usage[4];
            usages[0] = SymmetricKey.Usage.WRAP;
            usages[1] = SymmetricKey.Usage.UNWRAP;
            usages[2] = SymmetricKey.Usage.ENCRYPT;
            usages[3] = SymmetricKey.Usage.DECRYPT;

            kg.setKeyUsages(usages);
            kg.temporaryKeys(true);
            kg.initialize(128);
            tempKey = kg.generate();

            //unwrap the test aes keys onto the token

            Cipher encryptor = token.getCipherContext(EncryptionAlgorithm.AES_128_CBC);

            int ivLength = EncryptionAlgorithm.AES_128_CBC.getIVLength();
            byte[] iv = null;

            if (ivLength > 0) {
                iv = new byte[ivLength]; // all zeroes
            }

            encryptor.initEncrypt(tempKey, new IVParameterSpec(iv));
            byte[] wrappedKey = encryptor.doFinal(devKey);

            encryptor.initEncrypt(tempKey, new IVParameterSpec(iv));
            byte[]wrappedKey_test1 = encryptor.doFinal(devKey_test1);

            // 192 bit key

            TPSBuffer aesKey192Buf = new TPSBuffer(devKey192);
            TPSBuffer aesKey192Pad = new TPSBuffer(8);
            aesKey192Pad.setAt(0, (byte) 0x80);
            aesKey192Buf.add(aesKey192Pad);

            encryptor.initEncrypt(tempKey, new IVParameterSpec(iv));
            byte[] wrappedKey192 = encryptor.doFinal(aesKey192Buf.toBytesArray());

            // 128 bit key

            KeyWrapper keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.AES_CBC);
            keyWrap.initUnwrap(tempKey, new IVParameterSpec(iv));
            aes128 = keyWrap.unwrapSymmetric(wrappedKey, SymmetricKey.AES, 16);


            KeyWrapper keyWrap1 = token.getKeyWrapper(KeyWrapAlgorithm.AES_CBC);
            keyWrap1.initUnwrap(tempKey,new IVParameterSpec(iv));
            SymmetricKey aes128_test = keyWrap1.unwrapSymmetric(wrappedKey_test1,SymmetricKey.AES,16);

            System.out.println(new TPSBuffer(message_test1).toHexString());
            System.out.println(new TPSBuffer(devKey_test1).toHexString());
            System.out.println(new TPSBuffer(aes128_test.getKeyData()).toHexString());
            TPSBuffer input1 = new TPSBuffer(message_test1);
            TPSBuffer output1 = Util.computeAES_CMAC(aes128_test, input1);
            System.out.println("blub: " + output1.toHexString());

            // 192 bit key

            KeyWrapper keyWrap192 = token.getKeyWrapper(KeyWrapAlgorithm.AES_CBC);
            keyWrap192.initUnwrap(tempKey, new IVParameterSpec(iv));
            aes192 = keyWrap.unwrapSymmetric(wrappedKey192, SymmetricKey.AES, 24);

            // 256 bit key

            TPSBuffer aesKey256Buf = new TPSBuffer(devKey256);
            encryptor.initEncrypt(tempKey, new IVParameterSpec(iv));
            byte[] wrappedKey256 = encryptor.doFinal(aesKey256Buf.toBytesArray());

            KeyWrapper keyWrap256 = token.getKeyWrapper(KeyWrapAlgorithm.AES_CBC);
            keyWrap256.initUnwrap(tempKey, new IVParameterSpec(iv));
            aes256 = keyWrap.unwrapSymmetric(wrappedKey256, SymmetricKey.AES, 32);

            System.out.println("");
            System.out.println("Now use 128 bit AES key:");
            System.out.println("");

            //Attempt 0 bytes

            System.out.println("");
            System.out.println("Use message of 0 bytes:");
            System.out.println("");

            TPSBuffer input0 = new TPSBuffer(0);
            TPSBuffer output0 = Util.computeAES_CMAC(aes128, input0);

            System.out.println("Message:" + input0.toHexString());
            System.out.println("AES-CMAC output: " + output0.toHexString());
            System.out.println("");

            System.out.println("");
            System.out.println("Use message of 16 bytes:");
            System.out.println("");

            //Attempt 16 bytes

            TPSBuffer input = new TPSBuffer(message);
            TPSBuffer output = Util.computeAES_CMAC(aes128, input);

            System.out.println("Message:" + input.toHexString());
            System.out.println("AES-CMAC output: " + output.toHexString());
            System.out.println("");

            System.out.println("");
            System.out.println("Use message of 40 bytes:");
            System.out.println("");

            //Attempt 40 bytes

            TPSBuffer input320 = new TPSBuffer(message320);
            TPSBuffer output320 = Util.computeAES_CMAC(aes128, input320);

            System.out.println("Message:" + input320.toHexString());
            System.out.println("AES-CMAC output: " + output320.toHexString());
            System.out.println("");

            System.out.println("");
            System.out.println("Use message of 64 bytes:");
            System.out.println("");

            //Attempt 64 bytes

            TPSBuffer input512 = new TPSBuffer(message512);
            TPSBuffer output512 = Util.computeAES_CMAC(aes128, input512);
            System.out.println("Message:" + input512.toHexString());
            System.out.println("AES-CMAC output: " + output512.toHexString());

            // Now used the AES 192 key

            System.out.println("");
            System.out.println("Now use 192 bit AES key:");
            System.out.println("");

            System.out.println("");
            System.out.println("Use message of 0 bytes:");
            System.out.println("");

            // Attempt 0 bytes

            TPSBuffer input192_0 = new TPSBuffer(0);
            TPSBuffer output192_0 = Util.computeAES_CMAC(aes192, input192_0);
            System.out.println("Message:" + input192_0.toHexString());
            System.out.println("AES-CMAC output: " + output192_0.toHexString());
            System.out.println("");

            System.out.println("");
            System.out.println("Use message of 16 bytes:");
            System.out.println("");

            //Attempt 16 bytes

            TPSBuffer input192_128 = new TPSBuffer(message);
            TPSBuffer output192_128 = Util.computeAES_CMAC(aes192, input);
            System.out.println("Message:" + input192_128.toHexString());
            System.out.println("AES-CMAC output: " + output192_128.toHexString());
            System.out.println("");

            System.out.println("");
            System.out.println("Use message of 40 bytes:");
            System.out.println("");

            //Attempt 40 bytes

            TPSBuffer input192_320 = new TPSBuffer(message320);
            TPSBuffer output192_320 = Util.computeAES_CMAC(aes192, input192_320);
            System.out.println("Message:" + input192_320.toHexString());
            System.out.println("AES-CMAC output: " + output192_320.toHexString());
            System.out.println("");

            System.out.println("");
            System.out.println("Use message of 64 bytes:");
            System.out.println("");

            //Attempt 64 bytes

            TPSBuffer input192_512 = new TPSBuffer(message512);
            TPSBuffer output192_512 = Util.computeAES_CMAC(aes192, input512);
            System.out.println("Message:" + input192_512.toHexString());
            System.out.println("AES-CMAC output: " + output192_512.toHexString());

            System.out.println("");
            System.out.println("Now use 256 bit AES key:");
            System.out.println("");

            // Attempt 0 bytes

            TPSBuffer input256_0 = new TPSBuffer(0);
            TPSBuffer output256_0 = Util.computeAES_CMAC(aes256, input256_0);
            System.out.println("Message:" + input256_0.toHexString());
            System.out.println("AES-CMAC output: " + output256_0.toHexString());
            System.out.println("");

            //Attempt 16 bytes

            TPSBuffer input256_128 = new TPSBuffer(message);
            TPSBuffer output256_128 = Util.computeAES_CMAC(aes256, input256_128);
            System.out.println("Message:" + input256_128.toHexString());
            System.out.println("AES-CMAC output: " + output256_128.toHexString());
            System.out.println("");

            //Attempt 40 bytes

            TPSBuffer input256_320 = new TPSBuffer(message320);
            TPSBuffer output256_320 = Util.computeAES_CMAC(aes256, input256_320);
            System.out.println("Message:" + input256_320.toHexString());
            System.out.println("AES-CMAC output: " + output256_320.toHexString());
            System.out.println("");

            //Attempt 64 bytes

            TPSBuffer input256_512 = new TPSBuffer(message512);
            TPSBuffer output256_512 = Util.computeAES_CMAC(aes256, input256_512);
            System.out.println("Message:" + input256_512.toHexString());
            System.out.println("AES-CMAC output: " + output256_512.toHexString());

        } catch (AlreadyInitializedException e) {
            // it is ok if it is already initialized
        } catch (Exception e) {
            System.err.println("JSS error!" + e);
            System.exit(1);
        }
*/
    }


}
