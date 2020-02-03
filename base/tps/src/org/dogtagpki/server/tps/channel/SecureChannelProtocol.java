package org.dogtagpki.server.tps.channel;

import java.io.CharConversionException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;

import org.dogtagpki.tps.main.TPSBuffer;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.Cipher;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.IllegalBlockSizeException;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.SymmetricKeyDeriver;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.pkcs11.PKCS11Constants;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;

// It turns out that TPS only needs a small portion of the original TKS's SecureChannelProtocol class.
// Only implement here what tps needs. This could have been renamed as some sort of tps based util class
// but I would prefer to keep the name in order to minimize other cascading changes to the code.
// Also, we add methods from the Util class kept in common here, to place the CMAC crypto code within
// the tps package, instead of within pki-common.
public class SecureChannelProtocol {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SecureChannelProtocol.class);

    static String sharedSecretKeyName = null;
    static String masterKeyPrefix = null;

    static final int DEF_AES_KEYLENGTH = 16;
    static final int KEYLENGTH = 16;
    static final int PREFIXLENGHT = 128;
    static final int DES2_LENGTH = 16;
    static final int DES3_LENGTH = 24;
    static final int EIGHT_BYTES = 8;
    static final int KEYNAMELENGTH = PREFIXLENGHT + 7;
    static final String TRANSPORT_KEY_NAME = "sharedSecret";
    static final String DEFKEYSET_NAME = "defKeySet";
    static int protocol = 1;

    public static final String encType = "enc";
    public static final String macType = "mac";
    public static final String kekType = "kek";
    public static final String authType = "auth";
    public static final String dekType = "dek";
    public static final String rmacType = "rmac";
    public static final int PROTOCOL_ONE = 1;
    public static final int PROTOCOL_TWO = 2;
    public static final int PROTOCOL_THREE = 3;
    public static final int HOST_CRYPTOGRAM = 0;
    public static final int CARD_CRYPTOGRAM = 1;

    //Size of long type in bytes, since java7 has no define for this
    static final int LONG_SIZE = 8;

    //  constants

    static final int AES_128_BYTES = 16;
    static final int AES_192_BYTES = 24;
    static final int AES_256_BYTES = 32;

    static final int AES_128_BITS = 128;
    static final int AES_192_BITS = 192;
    static final int AES_256_BITS = 256;


    //SCP03 AES-CMAC related constants
    private static final byte AES_CMAC_CONSTANT = (byte) 0x87;
    private static final int AES_CMAC_BLOCK_SIZE = 16;

    public static final byte CARD_CRYPTO_KDF_CONSTANT_SCP03 = 0x0;
    public static final byte HOST_CRYPTO_KDF_CONSTANT_SCP03 = 0x1;


    /* DES KEY Parity conversion table. Takes each byte >> 1 as an index, returns
     * that byte with the proper parity bit set*/
    static final int parityTable[] =
    {
            /* Even...0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e */
            /* E */0x01, 0x02, 0x04, 0x07, 0x08, 0x0b, 0x0d, 0x0e,
            /* Odd....0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e */
            /* O */0x10, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f,
            /* Odd....0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e */
            /* O */0x20, 0x23, 0x25, 0x26, 0x29, 0x2a, 0x2c, 0x2f,
            /* Even...0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e */
            /* E */0x31, 0x32, 0x34, 0x37, 0x38, 0x3b, 0x3d, 0x3e,
            /* Odd....0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e */
            /* O */0x40, 0x43, 0x45, 0x46, 0x49, 0x4a, 0x4c, 0x4f,
            /* Even...0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e */
            /* E */0x51, 0x52, 0x54, 0x57, 0x58, 0x5b, 0x5d, 0x5e,
            /* Even...0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e */
            /* E */0x61, 0x62, 0x64, 0x67, 0x68, 0x6b, 0x6d, 0x6e,
            /* Odd....0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e */
            /* O */0x70, 0x73, 0x75, 0x76, 0x79, 0x7a, 0x7c, 0x7f,
            /* Odd....0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e */
            /* O */0x80, 0x83, 0x85, 0x86, 0x89, 0x8a, 0x8c, 0x8f,
            /* Even...0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e */
            /* E */0x91, 0x92, 0x94, 0x97, 0x98, 0x9b, 0x9d, 0x9e,
            /* Even...0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae */
            /* E */0xa1, 0xa2, 0xa4, 0xa7, 0xa8, 0xab, 0xad, 0xae,
            /* Odd....0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe */
            /* O */0xb0, 0xb3, 0xb5, 0xb6, 0xb9, 0xba, 0xbc, 0xbf,
            /* Even...0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce */
            /* E */0xc1, 0xc2, 0xc4, 0xc7, 0xc8, 0xcb, 0xcd, 0xce,
            /* Odd....0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde */
            /* O */0xd0, 0xd3, 0xd5, 0xd6, 0xd9, 0xda, 0xdc, 0xdf,
            /* Odd....0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee */
            /* O */0xe0, 0xe3, 0xe5, 0xe6, 0xe9, 0xea, 0xec, 0xef,
            /* Even...0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe */
            /* E */0xf1, 0xf2, 0xf4, 0xf7, 0xf8, 0xfb, 0xfd, 0xfe,
    };

    private SymmetricKey transportKey = null;
    CryptoManager cryptoManager = null;

    public SecureChannelProtocol() {
    }

    public SecureChannelProtocol(int theProtocol) {
        protocol = theProtocol;
    }

    public int getProtocol() {
        return protocol;
    }

    public SymmetricKey getSharedSecretKey(CryptoToken token) throws EBaseException {

        String method = "SecureChannelProtocol.getSharedSecretKey:";
        logger.debug(method + "entering: transportKey: " + transportKey);

        CryptoToken finalToken = token;
        CryptoToken internalToken = null;
        if (token == null) {

            logger.debug(method + " No token provided assume internal ");
            CryptoManager cm = null;
            try {
                cm = CryptoManager.getInstance();
                internalToken = returnTokenByName(CryptoUtil.INTERNAL_TOKEN_NAME, cm);
                finalToken = internalToken;
            } catch (NotInitializedException e) {
                logger.error(method + " " + e.getMessage(), e);
                throw new EBaseException(e);

            } catch (NoSuchTokenException e) {
                logger.error(method + " " + e.getMessage(), e);
                throw new EBaseException(e);
            }
        }

        if (transportKey == null) {
            transportKey = getSymKeyByName(finalToken, sharedSecretKeyName);
        }

        if (transportKey == null) {
            throw new EBaseException(method + "Can't locate shared secret key in token db.");
        }

        return transportKey;
    }

    public static String getSharedSecretKeyName(String name) throws EBaseException {

        String method = "SecureChannelProtocol.getSharedSecretKeyName:";
        logger.debug(method + " Entering...");

        // No longer cache the secret name, there could be a different one for each incoming TPS connection.
        if (name != null) {
            SecureChannelProtocol.sharedSecretKeyName = name;
        }

        if (SecureChannelProtocol.sharedSecretKeyName == null) {
            throw new EBaseException(method + " Can not find shared secret key name!");
        }

        return SecureChannelProtocol.sharedSecretKeyName;
    }

    public static String setSharedSecretKeyName(String name) throws EBaseException {
        return SecureChannelProtocol.getSharedSecretKeyName(name);
    }

    /* This routine will attempt to return one of the well known developer symmetric keys from the token.
    Each key, is merely stored on the token for convenience.
    If the given key is not found on the token it is put there and left on as a permanent key.
    From that point it is a simple matter of retrieving  the desired key from the token.
    No security advantage is implied or desired here.
    */
    public SymmetricKey returnDeveloperSymKey(CryptoToken token, String keyType, String keySet, byte[] inputKeyArray, String keyAlg)
            throws EBaseException {

        SymmetricKey devKey = null;

        String method = "SecureChannelProtocol.returnDeveloperSymKey:";

        boolean isAES = false;
        String finalAlg = null;
        if(keyAlg == null) {
            finalAlg = "DES3";
        }

        if(keyAlg.equalsIgnoreCase("AES")) {
            isAES = true;
            finalAlg = "AES";
        }

        String devKeyName = keySet + "-" + keyType + "Key"  + "-" + finalAlg;
        logger.debug(method + " entering.. searching for key: " + devKeyName);

        if (token == null || keyType == null || keySet == null) {
            throw new EBaseException(method + "Invalid input data!");
        }

        try {
            logger.debug(method + " requested token: " + token.getName());
        } catch (TokenException e) {
            throw new EBaseException(method + e);
        }

        devKey = getSymKeyByName(token, devKeyName);

        if (devKey == null) {
            //Put the key there and leave it

            byte[] des3InputKey = null;

            if (inputKeyArray == null) {
                throw new EBaseException(method + "Input key is null and has to be non null when importing...");
            }
            int inputLen = inputKeyArray.length;

            logger.debug(method + " inputKeyArray.length: " + inputLen);

            if (!isAES) {
                if (inputLen != DES3_LENGTH && inputLen != DES2_LENGTH) {
                    throw new EBaseException(method + "invalid input key length!");
                }

                if (inputLen == DES2_LENGTH) {
                    des3InputKey = new byte[DES3_LENGTH];
                    System.arraycopy(inputKeyArray, 0, des3InputKey, 0, DES2_LENGTH);
                    System.arraycopy(inputKeyArray, 0, des3InputKey, DES2_LENGTH, EIGHT_BYTES);

                } else {
                    System.arraycopy(inputKeyArray, 0, des3InputKey, 0, DES3_LENGTH);
                }

                //SecureChannelProtocol.debugByteArray(des3InputKey, "Developer key to import: " + keyType + ": ");

                devKey = unwrapSymKeyOnToken(token, des3InputKey, true);

            } else {

                if(inputLen == DEF_AES_KEYLENGTH) { // support 128 bits for now
                    devKey = unwrapAESSymKeyOnToken(token, inputKeyArray, true);
                }
            }

            devKey.setNickName(devKeyName);
        } else {
            logger.debug(method + " Found sym key: " + devKeyName);
        }
        return devKey;
    }

    //Takes raw des key 16 bytes, such as developer key and returns an AES key of the same size
    //Supports 128 bits for now
    public SymmetricKey unwrapAESSymKeyOnToken(CryptoToken token, byte[] inputKeyArray,
            boolean isPerm)
            throws EBaseException {

        String method = "SecureChannelProtocol.unwrapAESSymKeyOnToken:";
        logger.debug(method + "Entering...");

        if(token == null || inputKeyArray == null) {
            throw new EBaseException(method + " Invalid input data!");
        }

        if(inputKeyArray.length < 16) {
            throw new EBaseException(method + " Invalid key size!");
        }

        byte[] finalInputKeyArray = inputKeyArray;
        if(inputKeyArray.length > 16) {
            finalInputKeyArray = new byte[16];
            System.arraycopy(inputKeyArray, 0, finalInputKeyArray, 0, 16);;

        }

        KeyGenerator kg;
        SymmetricKey finalAESKey;
        try {
            kg = token.getKeyGenerator(KeyGenAlgorithm.AES);

            SymmetricKey.Usage usages[] = new SymmetricKey.Usage[4];
            usages[0] = SymmetricKey.Usage.WRAP;
            usages[1] = SymmetricKey.Usage.UNWRAP;
            usages[2] = SymmetricKey.Usage.ENCRYPT;
            usages[3] = SymmetricKey.Usage.DECRYPT;

            kg.setKeyUsages(usages);
            kg.temporaryKeys(true);
            kg.initialize(128);
            SymmetricKey tempKey = kg.generate();

            //unwrap the test aes keys onto the token

            Cipher encryptor = token.getCipherContext(EncryptionAlgorithm.AES_128_CBC);

            int ivLength = EncryptionAlgorithm.AES_128_CBC.getIVLength();
            byte[] iv = null;

            if (ivLength > 0) {
                iv = new byte[ivLength]; // all zeroes
            }

            encryptor.initEncrypt(tempKey, new IVParameterSpec(iv));
            byte[] wrappedKey = encryptor.doFinal(finalInputKeyArray);

            KeyWrapper keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.AES_CBC);
            keyWrap.initUnwrap(tempKey, new IVParameterSpec(iv));

            if(isPerm)
                finalAESKey = keyWrap.unwrapSymmetricPerm(wrappedKey, SymmetricKey.AES, AES_128_BYTES);
            else
                finalAESKey = keyWrap.unwrapSymmetric(wrappedKey, SymmetricKey.AES, AES_128_BYTES);


        } catch (Exception e) {
            throw new EBaseException(method + " Can't unwrap key onto token!");
        }

        return finalAESKey;
    }

    //Supports 128 bits for now
    //Used to convert a des key (on token) to aes
    //Not used as of now, future if needed
    public SymmetricKey unwrapAESSymKeyOnToken(CryptoToken token, SymmetricKey keyToUnwrap,
            boolean isPerm)
            throws EBaseException {

        String method = "SecureChannelProtocol.unwrapAESSymKeyOnToken:";
        logger.debug(method + "Entering...");

        if(token == null || keyToUnwrap == null) {
            throw new EBaseException(method + " Invalid input data!");
        }

        if(keyToUnwrap.getLength()< 16) {
            throw new EBaseException(method + " Invalid key size!");
        }

        CMSEngine engine = CMS.getCMSEngine();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();

        KeyGenerator kg;
        SymmetricKey finalAESKey;
        try {
            kg = token.getKeyGenerator(KeyGenAlgorithm.AES);

            SymmetricKey.Usage usages[] = new SymmetricKey.Usage[4];
            usages[0] = SymmetricKey.Usage.WRAP;
            usages[1] = SymmetricKey.Usage.UNWRAP;
            usages[2] = SymmetricKey.Usage.ENCRYPT;
            usages[3] = SymmetricKey.Usage.DECRYPT;

            kg.setKeyUsages(usages);
            kg.temporaryKeys(true);
            kg.initialize(128);
            SymmetricKey tempKey = kg.generate();


            int ivLength = EncryptionAlgorithm.AES_128_CBC.getIVLength();
            byte[] iv = null;

            if (ivLength > 0) {
                iv = new byte[ivLength]; // all zeroes
            }

            //Wrap the arbitrary key first

            int len = keyToUnwrap.getLength();

            SymmetricKey finalKeyToWrap = null;
            SymmetricKey key16 = null;
            if(len > 16) {
                key16 = extractDes2FromDes3(keyToUnwrap, token.getName());
                if(key16 != null)
                len = key16.getLength();
                finalKeyToWrap = key16;
            } else {
                finalKeyToWrap = keyToUnwrap;
            }

            KeyWrapper keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.AES_CBC);
            keyWrap.initWrap(tempKey, new IVParameterSpec(iv));
            byte[] wrappedKey = keyWrap.wrap(finalKeyToWrap);

            //Now unwrap to an AES key

            KeyWrapper keyUnWrap = token.getKeyWrapper(KeyWrapAlgorithm.AES_CBC);
            keyUnWrap.initUnwrap(tempKey, new IVParameterSpec(iv));
            finalAESKey = keyUnWrap.unwrapSymmetric(wrappedKey, SymmetricKey.AES, 16);

            jssSubsystem.obscureBytes(wrappedKey);

            //byte[] finalKeyBytes = finalAESKey.getKeyData();
            //displayByteArray(finalKeyBytes, false);

        } catch (Exception e) {
            throw new EBaseException(method + " Can't unwrap key onto token!");
        }

        return finalAESKey;

    }

    //Final param allows us to request the final type, DES or AES
    public SymmetricKey unwrapSymKeyOnToken(CryptoToken token, SymmetricKey unwrappingKey, byte[] inputKeyArray,
            boolean isPerm, SymmetricKey.Type finalKeyType)
            throws EBaseException {

        String method = "SecureChannelProtocol.unwrapSymKeyOnToken:";
        logger.debug(method + "Entering...");
        SymmetricKey unwrapped = null;
        SymmetricKey tempKey = null;

        if (token == null) {
            throw new EBaseException(method + "Invalid input!");
        }

        if (inputKeyArray == null || (inputKeyArray.length != DES3_LENGTH && inputKeyArray.length != DES2_LENGTH)) {
            throw new EBaseException(method + "No raw array to use to create key!");
        }

        if (unwrappingKey == null) {
            try {
                KeyGenerator kg = token.getKeyGenerator(KeyGenAlgorithm.DES3);

                SymmetricKey.Usage usages[] = new SymmetricKey.Usage[4];
                usages[0] = SymmetricKey.Usage.WRAP;
                usages[1] = SymmetricKey.Usage.UNWRAP;
                usages[2] = SymmetricKey.Usage.ENCRYPT;
                usages[3] = SymmetricKey.Usage.DECRYPT;

                kg.setKeyUsages(usages);
                kg.temporaryKeys(true);
                tempKey = kg.generate();
            } catch (NoSuchAlgorithmException | TokenException | IllegalStateException | CharConversionException e) {
                throw new EBaseException(method + "Can't generate temporary key to unwrap the key.");
            }

        }

        byte[] finalKeyArray = null;

        if (inputKeyArray.length == DES2_LENGTH && finalKeyType == SymmetricKey.DES3) {
            finalKeyArray = SecureChannelProtocol.makeDes3FromDes2(inputKeyArray);
        }

        Cipher encryptor = null;
        byte[] wrappedKey = null;

        SymmetricKey encUnwrapKey = null;

        if (tempKey != null) {
            encUnwrapKey = tempKey;
        } else {
            encUnwrapKey = unwrappingKey;
        }

        try {
            encryptor = token.getCipherContext(EncryptionAlgorithm.DES3_ECB);

            encryptor.initEncrypt(encUnwrapKey);

            if (finalKeyArray != null) {
                if(finalKeyType == SymmetricKey.Type.DES3 || finalKeyType == SymmetricKey.Type.DES)
                    wrappedKey = encryptor.doFinal(getDesParity(finalKeyArray));
                else
                    wrappedKey = encryptor.doFinal(finalKeyArray);
            } else {
                if(finalKeyType == SymmetricKey.Type.DES3 || finalKeyType == SymmetricKey.Type.DES)
                    wrappedKey = encryptor.doFinal(getDesParity(inputKeyArray));
                else
                    wrappedKey = encryptor.doFinal(inputKeyArray);
            }

            logger.debug(method + " done enrypting data");

            // SecureChannelProtocol.debugByteArray(wrappedKey, " encrypted key");

            KeyWrapper keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.DES3_ECB);
            keyWrap.initUnwrap(encUnwrapKey, null);

            if (isPerm == true) {
                unwrapped = keyWrap.unwrapSymmetricPerm(wrappedKey,
                        finalKeyType, 0);
            } else {
                unwrapped = keyWrap.unwrapSymmetric(wrappedKey, finalKeyType, 0);
            }

        } catch (Exception e) {
            logger.error(method + " " + e.getMessage(), e);
            throw new EBaseException(e);
        } finally {
            if (finalKeyArray != null) {
                Arrays.fill(finalKeyArray, (byte) 0);
            }
        }

        //logger.debug(method + "Returning symkey: " + unwrapped);
        logger.debug(method + "Returning symkey...");

        return unwrapped;
    }

    //Final param allows us to request the final type, DES or AES
    public SymmetricKey unwrapWrappedSymKeyOnToken(CryptoToken token, SymmetricKey unwrappingKey, byte[] inputKeyArray,
            boolean isPerm, SymmetricKey.Type keyType)
            throws EBaseException {

        String method = "SecureChannelProtocol.unwrapWrappedSymKeyOnToken:";
        logger.debug(method + "Entering...");
        SymmetricKey unwrapped = null;
        SymmetricKey finalUnwrapped = null;

        if (token == null || unwrappingKey == null) {
            throw new EBaseException(method + "Invalid input!");
        }

        if (inputKeyArray == null) {
            throw new EBaseException(method + "No raw array to use to create key!");
        }

        if(keyType == SymmetricKey.Type.AES) {
           if(inputKeyArray.length != DEF_AES_KEYLENGTH)
               throw new EBaseException(method + "Invalid length of raw input array.");
        }
        else if(keyType == SymmetricKey.Type.DES ||
                keyType == SymmetricKey.Type.DES3) {
            if(inputKeyArray.length != DES3_LENGTH && inputKeyArray.length != DES2_LENGTH)
                throw new EBaseException(method + "Invalid length of raw input array.");
        }

        try {
            KeyWrapper keyWrap;

            if(unwrappingKey.getType() == SymmetricKey.Type.AES)
            {
                IVParameterSpec iv = new IVParameterSpec(new byte[EncryptionAlgorithm.AES_128_CBC.getIVLength()]);
                keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.AES_CBC);
                keyWrap.initUnwrap(unwrappingKey, iv);
            }
            else if(unwrappingKey.getType() == SymmetricKey.Type.DES ||
                    unwrappingKey.getType() == SymmetricKey.Type.DES3)
            {
                keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.DES3_ECB);
                keyWrap.initUnwrap(unwrappingKey, null);
            }
            else
                throw new EBaseException(method + " Unsupported transport key type.");
            if (isPerm) {
                unwrapped = keyWrap.unwrapSymmetricPerm(inputKeyArray,
                        keyType, SymmetricKey.Usage.UNWRAP, inputKeyArray.length);
            } else {
                unwrapped = keyWrap.unwrapSymmetric(inputKeyArray, keyType, SymmetricKey.Usage.UNWRAP,
                        inputKeyArray.length);
            }

            if (keyType == SymmetricKey.DES3) {
                finalUnwrapped = makeDes3KeyDerivedFromDes2(unwrapped, token.getName());
            }

        } catch (Exception e) {
            logger.error(method + " " + e.getMessage(), e);
            throw new EBaseException(e);
        }

        //logger.debug(method + "Returning symkey: " + unwrapped);
        logger.debug(method + "Returning symkey...");

        if (finalUnwrapped != null)
            return finalUnwrapped;
        else
            return unwrapped;
    }

    public SymmetricKey unwrapSymKeyOnToken(CryptoToken token, byte[] inputKeyArray, boolean isPerm)
            throws EBaseException {

        String method = "SecureChannelProtocol.unwrapSymKeyOnToken:";
        logger.debug(method + "Entering...");
        SymmetricKey unwrapped = null;

        if (token == null) {
            throw new EBaseException(method + "Invalide crypto token!");
        }

        if (inputKeyArray == null || (inputKeyArray.length != DES3_LENGTH && inputKeyArray.length != DES2_LENGTH)) {
            throw new EBaseException(method + "No raw array to use to create key!");
        }

        SymmetricKey transport = getSharedSecretKey(token);
        unwrapped = this.unwrapSymKeyOnToken(token, transport, inputKeyArray, isPerm, SymmetricKey.DES3);

        //logger.debug(method + "Returning symkey: " + unwrapped);

        return unwrapped;
    }

    public static SymmetricKey getSymKeyByName(CryptoToken token, String name) throws EBaseException {

        String method = "SecureChannelProtocol.getSymKeyByName:";
        if (token == null || name == null) {
            throw new EBaseException(method + "Invalid input data!");
        }
        SymmetricKey[] keys;

        logger.debug(method + "Searching for sym key: " + name);
        try {
            keys = token.getCryptoStore().getSymmetricKeys();
        } catch (TokenException e) {
            throw new EBaseException(method + "Can't get the list of symmetric keys!");
        }
        int len = keys.length;
        for (int i = 0; i < len; i++) {
            SymmetricKey cur = keys[i];
            if (cur != null) {
                if (name.equals(cur.getNickName())) {
                    logger.debug(method + "Found key: " + name);
                    return cur;
                }
            }
        }

        logger.debug(method + " Sym Key not found.");
        return null;
    }

    public CryptoToken returnTokenByName(String name, CryptoManager manager) throws NoSuchTokenException, NotInitializedException {

        logger.debug("returnTokenByName: requested name: " + name);
        if (name == null || manager == null)
            throw new NoSuchTokenException();

        return CryptoUtil.getKeyStorageToken(name);
    }

    public static byte[] makeDes3FromDes2(byte[] des2) {

        if (des2 == null || des2.length != SecureChannelProtocol.DES2_LENGTH) {
            return null;
        }

        byte[] des3 = new byte[SecureChannelProtocol.DES3_LENGTH];

        System.arraycopy(des2, 0, des3, 0, SecureChannelProtocol.DES2_LENGTH);
        System.arraycopy(des2, 0, des3, DES2_LENGTH, EIGHT_BYTES);

        return des3;
    }

    public static void debugByteArray(byte[] array, String message) {

        logger.debug("About to dump array: " + message);
        System.out.println("About to dump array: " + message);

        if (array == null) {
            logger.debug("Array to dump is empty!");
            return;
        }

        System.out.println("################### ");
        logger.debug("################### ");

        String result = getHexString(array);
        logger.debug(result);
        System.out.println(result);
    }

    public static void
            displayByteArray(byte[] ba, boolean has_check_sum) {
        char mask = 0xff;

        if (has_check_sum == true)
            mask = 0xfe;

        for (int i = 0; i < ba.length; i++) {

            System.out.print(Integer.toHexString(ba[i] & mask) + " ");
            if ((i % 26) == 25) {
                System.out.println("");
            }
        }
        System.out.println("");
    }

    final protected static char[] hex = "0123456789abcdef".toCharArray();

    public static String getHexString(byte[] bytes) {

        char[] hexChars = new char[bytes.length * 3];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 3] = hex[v >>> 4];
            hexChars[j * 3 + 1] = hex[v & 0x0F];
            hexChars[j * 3 + 2] = ':';
        }
        return new String(hexChars);
    }

    public CryptoManager getCryptoManger() throws EBaseException {
        String method = "SecureChannelProtocol.getCryptoManager";
        CryptoManager cm = null;

        if (cryptoManager != null)
            return cryptoManager;

        try {
            cm = CryptoManager.getInstance();
        } catch (NotInitializedException e) {
            logger.error(method + " " + e.getMessage(), e);
            throw new EBaseException(e);

        }

        cryptoManager = cm;

        return cryptoManager;

    }

    public static byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(LONG_SIZE);
        buffer.putLong(x);
        return buffer.array();
    }

    /* Generate 24 key, but with a DES2 key converted to DES3
       This needed to appease the server side keygen and the coollkey applet.
    */
    public SymmetricKey generateSymKey(String selectedToken) throws EBaseException {
        String method = "SecureChannelProtocol.generateSymKey:";

        logger.debug(method + " entering , token: " + selectedToken);
        SymmetricKey symKey = null;
        SymmetricKey symKeyFinal = null;

        if (selectedToken == null) {
            throw new EBaseException(method + " Invalid input data!");
        }

        try {
            CryptoManager cm = this.getCryptoManger();
            CryptoToken token = returnTokenByName(selectedToken, cm);

            KeyGenerator kg = token.getKeyGenerator(KeyGenAlgorithm.DES3);

            symKey = kg.generate();

            symKeyFinal = this.makeDes3KeyDerivedFromDes2(symKey, selectedToken);

        } catch (Exception  e) {
            logger.error(method + " " + e.getMessage(), e);
            throw new EBaseException(e);
        }

        return symKeyFinal;

    }

    /* Convenience routine to create a 3DES key from a 2DES key.
    This is done by taking the first 8 bytes of the 2DES key and copying it to the end, making
     a faux 3DES key. This is required due to applet requirements.
    */
    public SymmetricKey makeDes3KeyDerivedFromDes2(SymmetricKey des3Key, String selectedToken) throws EBaseException {
        SymmetricKey des3 = null;

        String method = "SecureChannelProtocol.makeDes3KeyDerivedFromDes2:";

        logger.debug(method + " Entering ...");

        if (des3Key == null || selectedToken == null) {
            throw new EBaseException(method + " Invalid input data!");
        }

        try {
            CryptoManager cm = this.getCryptoManger();
            CryptoToken token = returnTokenByName(selectedToken, cm);

            long bitPosition = 0;

            byte[] param = SecureChannelProtocol.longToBytes(bitPosition);

            SymmetricKey extracted16 = this.extractDes2FromDes3(des3Key, selectedToken);

            SymmetricKeyDeriver extract8 = token.getSymmetricKeyDeriver();

            extract8.initDerive(
                    extracted16, PKCS11Constants.CKM_EXTRACT_KEY_FROM_KEY, param, null,
                    PKCS11Constants.CKA_ENCRYPT, PKCS11Constants.CKA_DERIVE, 8);

            SymmetricKey extracted8 = extract8.derive();

            //logger.debug(method + " extracted8 key: " + extracted8);
            logger.debug(method + " extracted8 key");

            SymmetricKeyDeriver concat = token.getSymmetricKeyDeriver();
            concat.initDerive(
                    extracted16, extracted8, PKCS11Constants.CKM_CONCATENATE_BASE_AND_KEY, null, null,
                    PKCS11Constants.CKM_DES3_ECB, PKCS11Constants.CKA_DERIVE, 0);

            des3 = concat.derive();

        } catch (Exception e) {
            logger.error(method + " " + e.getMessage(), e);
            throw new EBaseException(e);
        }

        return des3;
    }

    public SymmetricKey extractDes2FromDes3(SymmetricKey baseKey, String selectedToken) throws EBaseException {
        String method = "SecureChannelProtocol.extractDes2FromDes3:";
        logger.debug(method + " Entering: ");

        SymmetricKey extracted16 = null;

        if (baseKey == null || selectedToken == null) {
            throw new EBaseException(method + " Invalid input data.");
        }

        try {
            CryptoManager cm = this.getCryptoManger();
            CryptoToken token = returnTokenByName(selectedToken, cm);

            long bitPosition = 0;

            byte[] param = SecureChannelProtocol.longToBytes(bitPosition);

            SymmetricKeyDeriver extract16 = token.getSymmetricKeyDeriver();
            extract16.initDerive(
                    baseKey, PKCS11Constants.CKM_EXTRACT_KEY_FROM_KEY, param, null,
                    PKCS11Constants.CKA_ENCRYPT, PKCS11Constants.CKA_DERIVE, 16);

            extracted16 = extract16.derive();

        } catch (Exception e) {
            logger.error(method + " " + e.getMessage(), e);
            throw new EBaseException(e);
        }

        return extracted16;
    }

    /* If wrappingKey is not null, use it, otherwise use the shared secret key
    */
    public byte[] wrapSessionKey(String tokenName, SymmetricKey sessionKey, SymmetricKey wrappingKey)
            throws EBaseException {
        //Now wrap the key for the trip back to TPS with shared secret transport key

        String method = "SecureChannelProtocol.wrapSessionKey";

        KeyWrapper keyWrap = null;
        byte[] wrappedSessKeyData = null;

        if (tokenName == null || sessionKey == null) {
            throw new EBaseException(method + " Invalid input data.");
        }

        SymmetricKey wrapper = null;

        if (wrappingKey == null) {
            wrapper = transportKey;
        } else {
            wrapper = wrappingKey;
        }

        logger.debug(method + " wrapper key type: " + wrapper.getType());

        if (wrapper.getType() != SymmetricKey.AES) {
            logger.debug(method + "Trying to wrap a key with an DES key!");

            try {
                CryptoManager cm = this.getCryptoManger();
                CryptoToken token = returnTokenByName(tokenName, cm);

                keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.DES3_ECB);
                keyWrap.initWrap(wrapper, null);
                wrappedSessKeyData = keyWrap.wrap(sessionKey);

            } catch (Exception e) {
                logger.error(method + " " + e.getMessage(), e);
                throw new EBaseException(e);
            }

        } else if (wrapper.getType() == SymmetricKey.AES) {
            logger.debug(method + "Trying to wrap a key with an AES key!");
            try {
                CryptoManager cm = this.getCryptoManger();
                CryptoToken token = returnTokenByName(tokenName, cm);

                int ivLength = EncryptionAlgorithm.AES_128_CBC.getIVLength();
                byte[] iv = null;

                if (ivLength > 0) {
                    iv = new byte[ivLength]; // all zeroes
                }

                keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.AES_CBC);
                keyWrap.initWrap(wrapper, new IVParameterSpec(iv));
                wrappedSessKeyData = keyWrap.wrap(sessionKey);


            } catch (Exception e) {
                logger.error(method + " " + e.getMessage(), e);
                throw new EBaseException(e);
            }
        }


        //SecureChannelProtocol.debugByteArray(wrappedSessKeyData, "wrappedSessKeyData");
        logger.debug(method + " returning session key");

        return wrappedSessKeyData;

    }

    //128 for now.
    public byte[] computeAES_CBCEncryption(SymmetricKey symKey, String selectedToken, byte[] input, byte[] iv)
            throws EBaseException
    {
        String method = "SecureChannelProtocol.computeAES_CBCEncryption";
        byte[] output = null;
        byte[] finalIv = null;

        if (symKey == null || selectedToken == null) {
            throw new EBaseException(method + " Invalid input data.");
        }

        if (iv == null) {
            finalIv = new byte[16];

        } else {
            finalIv = iv;
        }

        try {
            CryptoManager cm = this.getCryptoManger();
            CryptoToken token = returnTokenByName(selectedToken, cm);
            Cipher encryptor = token.getCipherContext(EncryptionAlgorithm.AES_128_CBC);
            encryptor.initEncrypt(symKey, new IVParameterSpec(finalIv));
            output = encryptor.doFinal(input);

            //SecureChannelProtocol.debugByteArray(output, "Encrypted data:");
        } catch (Exception e) {

            logger.error(method + e.getMessage(), e);
            throw new EBaseException(method + e);
        }

        return output;
    }

    static public byte[] getDesParity(byte[] key) throws EBaseException {
        String method = "KDF.getDesParity";
        if (key == null || (key.length != SecureChannelProtocol.DES2_LENGTH &&
                key.length != SecureChannelProtocol.EIGHT_BYTES && key.length != SecureChannelProtocol.DES3_LENGTH)) {
            throw new EBaseException(method + " Incorrect input key !");
        }

        byte[] desKey = new byte[key.length];

        for (int i = 0; i < key.length; i++) {
            int index = key[i] & 0xff;
            int finalIndex = index >> 1;

            byte val = (byte) parityTable[finalIndex];
            desKey[i] = val;

        }

        logger.debug(method + "desKey: len: " + desKey.length);

        return desKey;
    }

    // AES CMAC related routines
    //

    public static TPSBuffer compute_AES_CMAC_Cryptogram(SymmetricKey symKey, TPSBuffer context, byte kdfConstant)
             throws EBaseException {

        String method = "SecureChannelProtocol.compute_AES_Crypto:";
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

            kI = SecureChannelProtocol.computeAES_CMAC(symKey, input);

            output.add(kI);
        }

        return output.substr(0,8);
    }

    public static TPSBuffer computeAES_CMAC(SymmetricKey aesKey, TPSBuffer input) throws EBaseException {

        String method = "SecureChannelProtocol.computeAES_CMAC:";
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


    public static void setDefaultPrefix(String masterkeyPrefix) {
        if (SecureChannelProtocol.masterKeyPrefix == null) {
            SecureChannelProtocol.masterKeyPrefix = masterkeyPrefix;
        }
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
            TPSBuffer output1 = SecureChannelProtocol.computeAES_CMAC(aes128_test, input1);
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
            TPSBuffer output0 = SecureChannelProtocol.computeAES_CMAC(aes128, input0);

            System.out.println("Message:" + input0.toHexString());
            System.out.println("AES-CMAC output: " + output0.toHexString());
            System.out.println("");

            System.out.println("");
            System.out.println("Use message of 16 bytes:");
            System.out.println("");

            //Attempt 16 bytes

            TPSBuffer input = new TPSBuffer(message);
            TPSBuffer output = SecureChannelProtocol.computeAES_CMAC(aes128, input);

            System.out.println("Message:" + input.toHexString());
            System.out.println("AES-CMAC output: " + output.toHexString());
            System.out.println("");

            System.out.println("");
            System.out.println("Use message of 40 bytes:");
            System.out.println("");

            //Attempt 40 bytes

            TPSBuffer input320 = new TPSBuffer(message320);
            TPSBuffer output320 = SecureChannelProtocol.computeAES_CMAC(aes128, input320);

            System.out.println("Message:" + input320.toHexString());
            System.out.println("AES-CMAC output: " + output320.toHexString());
            System.out.println("");

            System.out.println("");
            System.out.println("Use message of 64 bytes:");
            System.out.println("");

            //Attempt 64 bytes

            TPSBuffer input512 = new TPSBuffer(message512);
            TPSBuffer output512 = SecureChannelProtocol.computeAES_CMAC(aes128, input512);
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
            TPSBuffer output192_0 = SecureChannelProtocol.computeAES_CMAC(aes192, input192_0);
            System.out.println("Message:" + input192_0.toHexString());
            System.out.println("AES-CMAC output: " + output192_0.toHexString());
            System.out.println("");

            System.out.println("");
            System.out.println("Use message of 16 bytes:");
            System.out.println("");

            //Attempt 16 bytes

            TPSBuffer input192_128 = new TPSBuffer(message);
            TPSBuffer output192_128 = SecureChannelProtocol.computeAES_CMAC(aes192, input);
            System.out.println("Message:" + input192_128.toHexString());
            System.out.println("AES-CMAC output: " + output192_128.toHexString());
            System.out.println("");

            System.out.println("");
            System.out.println("Use message of 40 bytes:");
            System.out.println("");

            //Attempt 40 bytes

            TPSBuffer input192_320 = new TPSBuffer(message320);
            TPSBuffer output192_320 = SecureChannelProtocol.computeAES_CMAC(aes192, input192_320);
            System.out.println("Message:" + input192_320.toHexString());
            System.out.println("AES-CMAC output: " + output192_320.toHexString());
            System.out.println("");

            System.out.println("");
            System.out.println("Use message of 64 bytes:");
            System.out.println("");

            //Attempt 64 bytes

            TPSBuffer input192_512 = new TPSBuffer(message512);
            TPSBuffer output192_512 = SecureChannelProtocol.computeAES_CMAC(aes192, input512);
            System.out.println("Message:" + input192_512.toHexString());
            System.out.println("AES-CMAC output: " + output192_512.toHexString());

            System.out.println("");
            System.out.println("Now use 256 bit AES key:");
            System.out.println("");

            // Attempt 0 bytes

            TPSBuffer input256_0 = new TPSBuffer(0);
            TPSBuffer output256_0 = SecureChannelProtocol.computeAES_CMAC(aes256, input256_0);
            System.out.println("Message:" + input256_0.toHexString());
            System.out.println("AES-CMAC output: " + output256_0.toHexString());
            System.out.println("");

            //Attempt 16 bytes

            TPSBuffer input256_128 = new TPSBuffer(message);
            TPSBuffer output256_128 = SecureChannelProtocol.computeAES_CMAC(aes256, input256_128);
            System.out.println("Message:" + input256_128.toHexString());
            System.out.println("AES-CMAC output: " + output256_128.toHexString());
            System.out.println("");

            //Attempt 40 bytes

            TPSBuffer input256_320 = new TPSBuffer(message320);
            TPSBuffer output256_320 = SecureChannelProtocol.computeAES_CMAC(aes256, input256_320);
            System.out.println("Message:" + input256_320.toHexString());
            System.out.println("AES-CMAC output: " + output256_320.toHexString());
            System.out.println("");

            //Attempt 64 bytes

            TPSBuffer input256_512 = new TPSBuffer(message512);
            TPSBuffer output256_512 = SecureChannelProtocol.computeAES_CMAC(aes256, input256_512);
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
