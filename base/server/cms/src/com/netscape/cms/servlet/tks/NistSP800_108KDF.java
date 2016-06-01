package com.netscape.cms.servlet.tks;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.mozilla.jss.crypto.BadPaddingException;
import org.mozilla.jss.crypto.Cipher;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.HMACAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.IllegalBlockSizeException;
import org.mozilla.jss.crypto.JSSMessageDigest;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;

public class NistSP800_108KDF extends KDF {

    static final int KDF_OUTPUT_SIZE_BITS = 384;
    static final int KDF_OUTPUT_SIZE_BYTES = KDF_OUTPUT_SIZE_BITS / 8;
    static final int KEY_DATA_SIZE_BYTES = KDF_OUTPUT_SIZE_BYTES / 3;

    static final int KDD_SIZE_BYTES = 10; // expected KDD field length in bytes

    static final byte KDF_LABEL = 0x04; // arbitra

    //SCP03, AES related constants

    public static final int SHA256_LENGTH = 32;
    private static final int AES_CMAC_BLOCK_SIZE = 16;
    private static final byte AES_CMAC_CONSTANT = (byte) 0x87;
    public static final byte ENC_KDF_CONSTANT = (byte) 0x04;
    public static final byte MAC_KDF_CONSTANT = (byte) 0x06;
    public static final byte RMAC_KDF_CONSTANT = (byte) 0x07;
    public static final byte CARD_CRYPTO_KDF_CONSTANT = 0x0;
    public static final byte HOST_CRYPTO_KDF_CONSTANT = 0x1;



    SecureChannelProtocol protocol = null;

    NistSP800_108KDF(SecureChannelProtocol protocol) {
        this.protocol = protocol;
    }

    static public boolean useThisKDF(byte nistSP800_108KDFonKeyVersion, byte requestedKeyVersion) {
        return (requestedKeyVersion >= nistSP800_108KDFonKeyVersion);
    }

    /*******************************************************************************
     Generates three PK11SymKey objects using the KDF_CM_SHA256HMAC_L384() function for key data.
     After calling KDF_CM_SHA256HMAC_L384, the function splits up the output, sets DES parity,
       and imports the keys into the token.

     Careful:  This function currently generates the key data **IN RAM** using calls to NSS sha256.
                The key data is then "unwrapped" (imported) to the NSS token and then erased from RAM.
                (This means that a malicious actor on the box could steal the key data.)

     Note: Returned key material from the KDF is converted into keys according to the following:
       * Bytes 0  - 15 : enc/auth key
       * Bytes 16 - 31 : mac key
       * Bytes 32 - 47 : kek key
       We chose this order to conform with the key order used by the PUT KEY command.

    *******************************************************************************/

    public Map<String, SymmetricKey> computeCardKeys(SymmetricKey masterKey, byte[] context, CryptoToken token)
            throws EBaseException {

        String method = "NistSP800_108KDF.computeCardKeys:";

        if (masterKey == null || context == null || token == null) {
            throw new EBaseException(method + " Invalid input parameters!");
        }

        Map<String, SymmetricKey> keys = new HashMap<String, SymmetricKey>();

        byte[] kdf_output = null;

        kdf_output = kdf_CM_SHA256_HMAC_L384(masterKey, context, KDF_LABEL, KDF_OUTPUT_SIZE_BYTES, token);

        //Now create the 3 keys from only 48 of the 64 bytes...

        byte[] enc = new byte[16];
        byte[] mac = new byte[16];
        byte[] kek = new byte[16];

        System.arraycopy(kdf_output, 0 * SecureChannelProtocol.DES2_LENGTH, enc, 0, SecureChannelProtocol.DES2_LENGTH);
        System.arraycopy(kdf_output, 1 * SecureChannelProtocol.DES2_LENGTH, mac, 0, SecureChannelProtocol.DES2_LENGTH);
        System.arraycopy(kdf_output, 2 * SecureChannelProtocol.DES2_LENGTH, kek, 0, SecureChannelProtocol.DES2_LENGTH);

        byte[] encFinal = KDF.getDesParity(enc);
        byte[] macFinal = KDF.getDesParity(mac);
        byte[] kekFinal = KDF.getDesParity(kek);

        boolean showKeysOnlyForDebug = false;

        if (showKeysOnlyForDebug) {

            SecureChannelProtocol.debugByteArray(kdf_output, "kdf_CM_SHA256_HMAC_L384 output: ");

            SecureChannelProtocol.debugByteArray(mac, " Nist mac before parity: ");
            SecureChannelProtocol.debugByteArray(enc, " Nist enc before parity: ");
            SecureChannelProtocol.debugByteArray(kek, " Nist kek before parityl: ");


            SecureChannelProtocol.debugByteArray(macFinal, " Nist macFinal: ");
            SecureChannelProtocol.debugByteArray(encFinal, " Nist encFinal: ");
            SecureChannelProtocol.debugByteArray(kekFinal, " Nist kekFinal: ");
        }

        Arrays.fill(enc, (byte) 0);
        Arrays.fill(mac, (byte) 0);
        Arrays.fill(kek, (byte) 0);
        Arrays.fill(kdf_output, (byte) 0);

        SymmetricKey macKey = protocol.unwrapSymKeyOnToken(token, null, macFinal, false,SymmetricKey.DES3);
        SymmetricKey encKey = protocol.unwrapSymKeyOnToken(token, null, encFinal, false,SymmetricKey.DES3);
        SymmetricKey kekKey = protocol.unwrapSymKeyOnToken(token, null, kekFinal, false,SymmetricKey.DES3);

        Arrays.fill(encFinal, (byte) 0);
        Arrays.fill(macFinal, (byte) 0);
        Arrays.fill(kekFinal, (byte) 0);

        keys.put(SecureChannelProtocol.macType, macKey);
        keys.put(SecureChannelProtocol.encType, encKey);
        keys.put(SecureChannelProtocol.kekType, kekKey);

        return keys;

    }

    //Compute the AES based CMAC operation. Used to derive session keys and cryptograms
    public byte[] kdf_AES_CMAC_SCP03(SymmetricKey masterKey, byte[] context, byte kdfConstant,
            int kdfOutputSizeBytes) throws EBaseException {

        String method = "NistSP800_108KDF.kdf_AES_CMAC_SCP03:";
        // 11 bytes label
        byte[] label = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        // sanity checking

        if (masterKey == null || context == null || kdfOutputSizeBytes <= 0) {
            throw new EBaseException(method + " Invalid input!");
        }

        ByteArrayOutputStream data = new ByteArrayOutputStream();

        int outputBits = kdfOutputSizeBytes * 8;

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

        byte[] outputBitsBinary = new byte[2];
        outputBitsBinary[0] = b1;
        outputBitsBinary[1] = b2;

        try {
            data.write(label);
            data.write(kdfConstant);
            data.write(0x0);
            data.write(outputBitsBinary);
        } catch (IOException e) {
            throw new EBaseException(method + "Unable to calculate kdf!");
        }

        byte[] headerBytes = data.toByteArray();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ByteArrayOutputStream input = new ByteArrayOutputStream();

        byte[] kI = null;
        for (int i = 1; i <= n; i++) {

            try {
                input.write(headerBytes);
                input.write((byte) i);
                input.write(context);

                kI = computeAES_CMAC(masterKey, input.toByteArray());

                output.write(kI);

            } catch (IOException e) {
                throw new EBaseException(method + "Unable to calculate kdf!");
            }

        }

        return output.toByteArray();
    }

    /*******************************************************************************
     Key Derivation Function in Counter Mode using PRF = SHA256HMAC (NIST SP 800-108)
       Calculates 384 bits of diversified output from the provided master key (K_I)
    *******************************************************************************/

    private byte[] kdf_CM_SHA256_HMAC_L384(SymmetricKey masterKey, byte[] context, byte kdfLabel,
            int kdfOutputSizeBytes, CryptoToken token) throws EBaseException {

        String method = "NistSP800_108KDF.kdf_CM_SHA256_HMAC_L384:";

        CMS.debug(method + " entering..");
        final byte n = 2; // ceil(384 / (SHA256LENGTH * 8)) == 2
        int L_BYTE_array_length = 2; // 384 = 0x0180 hex; 2 byte long representation

        if (context == null) {
        }
        // sanity check that output buffer is large enough to contain 384 bits
        if (kdfOutputSizeBytes < KDF_OUTPUT_SIZE_BYTES) {
            throw new EBaseException(method + " Array \"output\" must be at least 48 bytes in size.");
        }

        // calculate size of temporary buffer
        int HMAC_DATA_INPUT_SIZE = context.length + 3 + L_BYTE_array_length; // Don't change without reviewing code below.

        // prevent integer overflow
        if (HMAC_DATA_INPUT_SIZE < context.length) {
            throw new EBaseException(method + " Input parameter context size is too large.");
        }

        byte L_BYTE_array[] = new byte[L_BYTE_array_length]; // Array to store L in BYTES
        L_BYTE_array[0] = 0x01;
        L_BYTE_array[1] = (byte) 0x80;

        // Hash Input = context + 5 BYTES
        byte[] hmac_data_input = new byte[HMAC_DATA_INPUT_SIZE];

        byte[] K = new byte[n * SHA256_LENGTH];

        hmac_data_input[1] = kdfLabel;
        hmac_data_input[2] = 0x0;
        System.arraycopy(context, 0, hmac_data_input, 3, context.length);
        System.arraycopy(L_BYTE_array, 0, hmac_data_input, context.length + 3, 2);

        byte[] outputHMAC256 = null;

        for (byte i = 1; i <= n; i++) {
            hmac_data_input[0] = i;
            outputHMAC256 = sha256HMAC(masterKey, hmac_data_input, HMAC_DATA_INPUT_SIZE, token);
            CMS.debug(method + "outputHMAC256 len: " + outputHMAC256.length);
            System.arraycopy(outputHMAC256, 0, K, (i - 1) * SHA256_LENGTH, SHA256_LENGTH);
            Arrays.fill(outputHMAC256, (byte)0);
        }

        CMS.debug(method + " Full array: " + K.length + " bytes...");

        byte[] finalOutput = new byte[KDF_OUTPUT_SIZE_BYTES];

        System.arraycopy(K, 0, finalOutput, 0, KDF_OUTPUT_SIZE_BYTES);

        Arrays.fill(K, (byte) 0);

        CMS.debug(method + " finalOutput: " + finalOutput.length + " bytes...");

        return finalOutput;
    }

    private byte[] sha256HMAC(SymmetricKey masterKey, // HMAC Secret Key (K_I)
            byte[] hmac_data_input, // HMAC Input (i||04||00||context||0180)
            int hMAC_DATA_INPUT_SIZE, // Input Length
            CryptoToken token) throws EBaseException {

        String method = "NistSP800_108KDF.sha256HMAC:";

        CMS.debug(method + " Entering...");

        byte[] digestBytes = null;

        if (token == null) {
            throw new EBaseException(method = " Invalid Crypto Token input!");
        }

        try {
            JSSMessageDigest digest = token.getDigestContext(HMACAlgorithm.SHA256);
            digest.initHMAC(masterKey);

            digestBytes = digest.digest(hmac_data_input);
        } catch (Exception e) {

            CMS.debug(method + " Failure to HMAC the input data: " + e);
            throw new EBaseException(method + e);
        }

        // SecureChannelProtocol.debugByteArray(digestBytes, " output of sha256HMAC: ");

        return digestBytes;
    }

    // Implements agorithm http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38b.pdf
    // Input an aes key of 128, 192, or 256 bits
    // For now calling code only using 128
    // Will move later to common class used by both tks and tps

    public static byte[] computeAES_CMAC(SymmetricKey aesKey, byte[] input) throws EBaseException {

        String method = "NistSP800_108KDF.computeAES_CMAC:";
        byte iv[] = null;

        if (aesKey == null || input == null) {
            throw new EBaseException(method + " invalid input data!");
        }

        byte[] data = new byte[input.length];
        System.arraycopy(input, 0, data, 0, input.length);

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
        int messageSize = data.length;;
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

        byte[] finalData = null;
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );

        if (perfectBlocks == true)
        {
            // If the size of the message is an integer multiple of the block  block size (namely, 128 bits) (16 bytes)
            // the last block shall be exclusive-OR'ed with the first subKey k1

            for (int j = 0; j < k1.length; j++) {
                index = messageSize - AES_CMAC_BLOCK_SIZE + j;
                inb = data[index];
                data[index] = (byte) (inb ^ k1[j]);
            }
            try {
                outputStream.write(data);
            } catch (IOException e) {
                throw new EBaseException(method + " internal buffer erro!");
            }
            finalData = outputStream.toByteArray();
        }
        else
        {
            // Otherwise, the last block shall be padded with 10^i
            byte[] padding = new byte[AES_CMAC_BLOCK_SIZE - messageSize % AES_CMAC_BLOCK_SIZE];
            padding[0] = (byte) 0x80;

            try {
                outputStream.write(data);
                outputStream.write(padding);
            } catch (IOException e) {
                throw new EBaseException(method + " internal buffer error!");
            }

            finalData = outputStream.toByteArray();

            //Get new data size , it's changed
            messageSize = finalData.length;

            // and exclusive-OR'ed with K2
            for (int j = 0; j < k2.length; j++) {
                index = messageSize - AES_CMAC_BLOCK_SIZE + j;
                inb = finalData[index];
                finalData[index] = (byte) (inb ^ k2[j]);
            }
        }

        // Initialization vector starts as zeroes but changes inside the loop's
        // subsequent iterations, it becomes the last encryption output
        byte[] encData = new byte[AES_CMAC_BLOCK_SIZE];
        byte[] currentBlock = new byte[AES_CMAC_BLOCK_SIZE];
        for (int i = 0; i < numBlocks; i++) {
            try {
                encryptor.initEncrypt(aesKey, new IVParameterSpec(encData));
                System.arraycopy(finalData, i * AES_CMAC_BLOCK_SIZE, currentBlock, 0, AES_CMAC_BLOCK_SIZE);
                encData = encryptor.doFinal(currentBlock);
            } catch (TokenException | IllegalStateException | IllegalBlockSizeException
                    | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
                throw new EBaseException(e);
            }
        }

        return encData;

    }

    // SCP03 AES-CMAC support function
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

    // Collection of informal invocations of api used to create various session keys
    // Done with test data.
    public static void main(String[] args) {
/*
      Options options = new Options();

        options.addOption("d", true, "Directory for tokendb");

        String db_dir = null;
        CryptoManager cm = null;

        byte devKey[] = { (byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44, (byte) 0x45, (byte) 0x46,
                (byte) 0x47, (byte) 0x48, (byte) 0x49, (byte) 0x4a, (byte) 0x4b, (byte) 0x4c, (byte) 0x4d, (byte) 0x4e,
                (byte) 0x4f };

        byte test_cuid[] = { (byte) 0x47,(byte) 0x90,(byte)0x50,(byte)0x37,(byte)0x72,(byte)0x71,(byte)0x97,(byte)0x00,(byte)0x74,(byte)0xA9 };
        byte test_kdd[] = { (byte)0x00, (byte)0x00, (byte)0x50, (byte)0x24,(byte) 0x97,(byte) 0x00,(byte) 0x74, (byte) 0xA9, (byte)0x72,(byte)0x71 };


        byte test_host_challenge[]  = { 0x06 ,(byte)0xA4 ,0x46 ,0x57 ,(byte) 0x8B ,0x65 ,0x48 ,0x51 };
        byte test_card_challenge[]  = { (byte) 0xAD ,(byte) 0x2E ,(byte)0xD0 ,0x1E ,0x7C ,0x2D ,0x0C ,0x6F};

        byte test_key_info[] = { (byte) 0x02,(byte) 03,(byte) 00 };
        byte test_old_key_info[] = {0x01,0x03,0x00};

        try {
            CommandLineParser parser = new DefaultParser();
            CommandLine cmd = parser.parse(options, args);

            if (cmd.hasOption("d")) {
                db_dir = cmd.getOptionValue("d");
            }

        } catch (ParseException e) {
            System.err.println("Error in parsing command line options: " + e.getMessage());

        }

        SymmetricKey encKey = null;
        SymmetricKey macKey = null;
        SymmetricKey kekKey = null;

        SymmetricKey putEncKey = null;
        SymmetricKey putMacKey = null;
        SymmetricKey putKekKey = null;

        SymmetricKey tempKey = null;

        try {
            CryptoManager.initialize(db_dir);
            cm = CryptoManager.getInstance();

            CryptoToken token = cm.getInternalKeyStorageToken();

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


            Cipher encryptor = token.getCipherContext(EncryptionAlgorithm.AES_128_CBC);

            int ivLength = EncryptionAlgorithm.AES_128_CBC.getIVLength();
            byte[] iv = null;

            if (ivLength > 0) {
                iv = new byte[ivLength]; // all zeroes
            }

            encryptor.initEncrypt(tempKey, new IVParameterSpec(iv));
            byte[] wrappedKey = encryptor.doFinal(devKey);

            KeyWrapper keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.AES_CBC);
            keyWrap.initUnwrap(tempKey, new IVParameterSpec(iv));

            encKey = keyWrap.unwrapSymmetric(wrappedKey, SymmetricKey.DES3, 16);
            macKey = keyWrap.unwrapSymmetric(wrappedKey, SymmetricKey.DES3, 16);
            kekKey = keyWrap.unwrapSymmetric(wrappedKey, SymmetricKey.DES3, 16);

            String transportName = "TPS-dhcp-16-206.sjc.redhat.com-8443 sharedSecret";
            SecureChannelProtocol prot = new SecureChannelProtocol(SecureChannelProtocol.PROTOCOL_THREE);

            SymmetricKey masterKey =  SecureChannelProtocol.getSymKeyByName(token,"new_master");

            GPParams params = new GPParams();
            params.setVersion1DiversificationScheme("visa2");
            params.setDiversificationScheme("visa2");

            putEncKey = prot.computeSessionKey_SCP03("internal", "new_master",test_old_key_info,
                    SecureChannelProtocol.encType, devKey, "defKeySet", test_cuid, test_kdd, null, null,
                    transportName,params);

            putMacKey = prot.computeSessionKey_SCP03("internal", "new_master",test_old_key_info,
                    SecureChannelProtocol.macType, devKey, "defKeySet", test_cuid, test_kdd, null, null,
                    transportName,params);

            putKekKey = prot.computeSessionKey_SCP03("internal", "new_master",test_old_key_info,
                    SecureChannelProtocol.kekType, devKey, "defKeySet", test_cuid, test_kdd, null, null,
                    transportName,params);

            //create test session keys
            encKey = prot.computeSessionKey_SCP03("internal", "new_master",test_key_info,
                    SecureChannelProtocol.encType, devKey, "defKeySet", test_cuid, test_kdd, test_host_challenge, test_card_challenge,
                    transportName,params);

            macKey = prot.computeSessionKey_SCP03("internal", "new_master",test_key_info,
                    SecureChannelProtocol.macType,devKey,"defKeySet", test_cuid, test_kdd, test_host_challenge, test_card_challenge,
                    transportName,params);

            kekKey = prot.computeSessionKey_SCP03("internal", "new_master",test_key_info,
                    SecureChannelProtocol.kekType, devKey, "defKeySet", test_cuid, test_kdd, test_host_challenge, test_card_challenge,
                    transportName,params);

            System.out.println("masterKey: " + masterKey);

            System.out.println("\n");

            SecureChannelProtocol.debugByteArray(putEncKey.getKeyData(), " derived putEnc session key data: ");
            SecureChannelProtocol.debugByteArray(putMacKey.getKeyData(), " derived putMac session key data: ");
            SecureChannelProtocol.debugByteArray(putKekKey.getKeyData(), " derived putKek session key data: ");

            System.out.println("\n");

            SecureChannelProtocol.debugByteArray(encKey.getKeyData(), " derived enc session key data: ");
            SecureChannelProtocol.debugByteArray(macKey.getKeyData(), " derived mac session key data: ");
            SecureChannelProtocol.debugByteArray(kekKey.getKeyData(), " derived kek session key data: ");

            ByteArrayOutputStream contextStream = new ByteArrayOutputStream();
            try {
                contextStream.write(test_host_challenge);
                contextStream.write(test_card_challenge);
            } catch (IOException e) {
            }

            StandardKDF standard = new StandardKDF(prot);

            ByteArrayOutputStream testContext = new ByteArrayOutputStream();

            testContext.write(test_host_challenge);
            testContext.write(test_card_challenge);

            NistSP800_108KDF  nistKdf = new NistSP800_108KDF(prot);

            byte[] finalEncBytes = nistKdf.kdf_AES_CMAC_SCP03(encKey, testContext.toByteArray(), (byte) 0x04, 16);
            byte[] finalMacBytes = nistKdf.kdf_AES_CMAC_SCP03(macKey, testContext.toByteArray(), (byte) 0x06, 16);

            SymmetricKey sEnc  = prot.unwrapAESSymKeyOnToken(token, finalEncBytes, false);
            SymmetricKey sMac  = macKey = prot.unwrapAESSymKeyOnToken(token, finalMacBytes, false);

            byte[] cardCryptoVerify = nistKdf.kdf_AES_CMAC_SCP03(sMac, testContext.toByteArray(), CARD_CRYPTO_KDF_CONSTANT, 8);
            SecureChannelProtocol.debugByteArray(cardCryptoVerify, " calculated card cryptogram");

            byte[] hostCrypto = nistKdf.kdf_AES_CMAC_SCP03(sMac, testContext.toByteArray(), HOST_CRYPTO_KDF_CONSTANT, 8);
            SecureChannelProtocol.debugByteArray(hostCrypto, " calculated host cryptogram");

        } catch (AlreadyInitializedException e) {
            // it is ok if it is already initialized
        } catch (Exception e) {
            System.err.println("JSS error!" + e);
            System.exit(1);
        }
*/
    }
}
