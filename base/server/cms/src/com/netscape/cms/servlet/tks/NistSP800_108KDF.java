package com.netscape.cms.servlet.tks;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.HMACAlgorithm;
import org.mozilla.jss.crypto.JSSMessageDigest;
import org.mozilla.jss.crypto.SymmetricKey;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;

public class NistSP800_108KDF extends KDF {

    static final int KDF_OUTPUT_SIZE_BITS = 384;
    static final int KDF_OUTPUT_SIZE_BYTES = KDF_OUTPUT_SIZE_BITS / 8;
    static final int KEY_DATA_SIZE_BYTES = KDF_OUTPUT_SIZE_BYTES / 3;

    static final int KDD_SIZE_BYTES = 10; // expected KDD field length in bytes

    static final byte KDF_LABEL = 0x04; // arbitra

    static final int SHA256_LENGTH = 32;

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
            throw new EBaseException(method + " Invlalid input parameters!");
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

        SymmetricKey macKey = protocol.unwrapSymKeyOnToken(token, null, macFinal, false);
        SymmetricKey encKey = protocol.unwrapSymKeyOnToken(token, null, encFinal, false);
        SymmetricKey kekKey = protocol.unwrapSymKeyOnToken(token, null, kekFinal, false);

        Arrays.fill(encFinal, (byte) 0);
        Arrays.fill(macFinal, (byte) 0);
        Arrays.fill(kekFinal, (byte) 0);

        keys.put(SecureChannelProtocol.macType, macKey);
        keys.put(SecureChannelProtocol.encType, encKey);
        keys.put(SecureChannelProtocol.kekType, kekKey);

        return keys;

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
            throw new EBaseException(method + " Input value context  must not be null.");
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

}
