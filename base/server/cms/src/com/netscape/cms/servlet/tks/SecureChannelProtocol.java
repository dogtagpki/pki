package com.netscape.cms.servlet.tks;

import java.io.ByteArrayOutputStream;
import java.io.CharConversionException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Map;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.crypto.BadPaddingException;
import org.mozilla.jss.crypto.Cipher;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IllegalBlockSizeException;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.SymmetricKey.NotExtractableException;
import org.mozilla.jss.crypto.SymmetricKeyDeriver;
import org.mozilla.jss.crypto.TokenException;

import sun.security.pkcs11.wrapper.PKCS11Constants;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;

public class SecureChannelProtocol {

    static String sharedSecretKeyName = null;
    static String masterKeyPrefix = null;

    static final int KEYLENGTH = 16;
    static final int PREFIXLENGHT = 128;
    static final int DES2_LENGTH = 16;
    static final int DES3_LENGTH = 24;
    static final int EIGHT_BYTES = 8;
    static final int KEYNAMELENGTH = PREFIXLENGHT + 7;
    static final String TRANSPORT_KEY_NAME = "sharedSecret";
    static final String DEFKEYSET_NAME = "defKeySet";

    static final String encType = "enc";
    static final String macType = "mac";
    static final String kekType = "kek";
    static final String authType = "auth";
    static final String dekType = "dek";
    static final int PROTOCOL_ONE = 1;
    static final int PROTOCOL_TWO = 2;
    static final int PROTOCOL_THREE = 3;
    static final int HOST_CRYPTOGRAM = 0;
    static final int CARD_CRYPTOGRAM = 1;

    private SymmetricKey transportKey = null;
    CryptoManager cryptoManager = null;

    public SecureChannelProtocol() {
    }

    public byte[] computeCryptogram_SCP01(
            String selectedToken, String keyNickName, byte[] card_challenge,
            byte[] host_challenge, byte[] keyInfo,
            byte nistSP800_108KdfOnKeyVersion, // AC: KDF SPEC CHANGE - pass in configuration file value
            boolean nistSP800_108KdfUseCuidAsKdd, // AC: KDF SPEC CHANGE - pass in configuration file value
            byte[] xCUID, // AC: KDF SPEC CHANGE - removed duplicative 'CUID' variable and replaced with 'xCUID'
            byte[] xKDD, // AC: KDF SPEC CHANGE - pass in KDD so symkey can make decision about which value (KDD,CUID) to use
            int cryptogramType, byte[] authKeyArray, String useSoftToken_s, String keySet, String transportKeyName)
            throws EBaseException {

        String method = "SecureChannelProtocol.computeCryptogram_SCP01:";

        CMS.debug(method + " Entering:  Type:  HOST=0 , CARD=1 : TYPE: " + cryptogramType);

        if ((card_challenge == null || card_challenge.length != EIGHT_BYTES)
                || (host_challenge == null || host_challenge.length != EIGHT_BYTES)) {

            throw new EBaseException(method + " Invalid card challenge or host challenge!");

        }

        if (cryptogramType != HOST_CRYPTOGRAM && cryptogramType != CARD_CRYPTOGRAM) {
            throw new EBaseException(method + " Invalid cyrptgram type!");
        }

        byte[] cryptogram = null;

        SymmetricKey authKey = this.computeSessionKey_SCP01(SecureChannelProtocol.encType, selectedToken, keyNickName,
                card_challenge, host_challenge, keyInfo, nistSP800_108KdfOnKeyVersion, nistSP800_108KdfUseCuidAsKdd,
                xCUID, xKDD, authKeyArray, useSoftToken_s, keySet, transportKeyName);

        byte[] input = new byte[DES2_LENGTH];
        byte[] icv = new byte[EIGHT_BYTES];

        if (cryptogramType == HOST_CRYPTOGRAM) // compute host cryptogram
        {
            /* copy card and host challenge into input buffer */
            for (int i = 0; i < EIGHT_BYTES; i++)
            {
                input[i] = card_challenge[i];
            }
            for (int i = 0; i < EIGHT_BYTES; i++)
            {
                input[EIGHT_BYTES + i] = host_challenge[i];
            }
        } // compute card cryptogram
        else if (cryptogramType == CARD_CRYPTOGRAM)
        {
            for (int i = 0; i < EIGHT_BYTES; i++)
            {
                input[i] = host_challenge[i];
            }
            for (int i = 0; i < EIGHT_BYTES; i++)
            {
                input[EIGHT_BYTES + i] = card_challenge[i];
            }

        }
        cryptogram = computeMAC_SCP01(authKey, input, icv, selectedToken);

        // SecureChannelProtocol.debugByteArray(cryptogram, " Output of computeCrytptogram type: " + cryptogramType);

        return cryptogram;
    }

    public SymmetricKey computeSessionKey_SCP02(
            String selectedToken, String keyNickName,
            byte[] keyInfo,
            byte nistSP800_108KdfOnKeyVersion, // AC: KDF SPEC CHANGE - pass in configuration file value
            boolean nistSP800_108KdfUseCuidAsKdd, byte[] xCUID, byte[] xKDD, byte[] macKeyArray,
            byte[] sequenceCounter, byte[] derivationConstant,
            String useSoftToken_s, String keySet,
            String transportKeyName) throws EBaseException {

        String method = "SecureChannelProtocol.computeSessionKey_SCP01:";

        CMS.debug(method + " entering... ");

        throw new EBaseException(method + " Not yet implemented!");
    }

    public SymmetricKey computeKEKKey_SCP01(
            String selectedToken, String keyNickName,
            byte[] keyInfo,
            byte nistSP800_108KdfOnKeyVersion, // AC: KDF SPEC CHANGE - pass in configuration file value
            boolean nistSP800_108KdfUseCuidAsKdd, // AC: KDF SPEC CHANGE - pass in configuration file value
            byte[] xCUID, // AC: KDF SPEC CHANGE - removed duplicative 'CUID' variable and replaced with 'xCUID'
            byte[] xKDD, // AC: KDF SPEC CHANGE - pass in KDD so symkey can make decision about which value (KDD,CUID) to use
            byte[] devKeyArray, String useSoftToken_s, String keySet, String transportKeyName) throws EBaseException {


        String method = "SecureChannelProtocol.computeKEKKey_SCP01:";

        CMS.debug(method + " entering... ");

        return computeSessionKey_SCP01(SecureChannelProtocol.kekType, selectedToken, keyNickName, null, null, keyInfo,
                nistSP800_108KdfOnKeyVersion, nistSP800_108KdfUseCuidAsKdd, xCUID, xKDD, devKeyArray, useSoftToken_s,
                keySet, transportKeyName);

    }

    public SymmetricKey computeSessionKey_SCP01(String keyType,
            String selectedToken, String keyNickName, byte[] card_challenge,
            byte[] host_challenge, byte[] keyInfo,
            byte nistSP800_108KdfOnKeyVersion, // AC: KDF SPEC CHANGE - pass in configuration file value
            boolean nistSP800_108KdfUseCuidAsKdd, // AC: KDF SPEC CHANGE - pass in configuration file value
            byte[] xCUID, // AC: KDF SPEC CHANGE - removed duplicative 'CUID' variable and replaced with 'xCUID'
            byte[] xKDD, // AC: KDF SPEC CHANGE - pass in KDD so symkey can make decision about which value (KDD,CUID) to use
            byte[] devKeyArray, String useSoftToken_s, String keySet, String transportKeyName) throws EBaseException {

        String method = "SecureChannelProtocol.computeSessionKey_SCP01:";

        CMS.debug(method + " entering... requested type: " + keyType);

        // This gets set if there is no input card challenge and host challenge
        // Allows this routine to be used for the "encryptData" routine built on top.

        boolean noDerive = false;

        if (keyType == null || devKeyArray == null || keyInfo == null
                || keySet == null || transportKeyName == null || (keyInfo == null || keyInfo.length < 2)) {
            throw new EBaseException(method + "Invalid input!");
        }

        if (xCUID == null || xCUID.length <= 0) {
            throw new EBaseException(method + "CUID invalid size!");
        }

        if (xKDD == null || xKDD.length != NistSP800_108KDF.KDD_SIZE_BYTES) {
            throw new EBaseException(method + "KDD invalid size!");
        }

        if (card_challenge == null && host_challenge == null) {
            noDerive = true;
            CMS.debug(method + " NoDerive mode: true");
        } else {
            if (card_challenge == null || host_challenge == null) {
                throw new EBaseException(method + " Invalid input!");
            }

            CMS.debug(method + " NoDerive mode: false");
        }

        CMS.debug(method + " entering. nickname: " + keyNickName + " selectedToken: " + selectedToken);
        CMS.debug(method + " nistSP800_108kdfOnKeyVersion: " + nistSP800_108KdfOnKeyVersion);

        CryptoManager cm = null;
        CryptoToken token = null;
        CryptoToken internalToken = null;
        try {
            cm = CryptoManager.getInstance();
            token = returnTokenByName(selectedToken, cm);
            internalToken = returnTokenByName("internal", cm);
        } catch (NotInitializedException e) {
            CMS.debug(method + " " + e);
            throw new EBaseException(e);

        } catch (NoSuchTokenException e) {
            CMS.debug(method + " " + e);
            throw new EBaseException(e);
        }

        sharedSecretKeyName = SecureChannelProtocol.getSharedSecretKeyName(transportKeyName);

        transportKey = getSharedSecretKey(internalToken);

        String keyNameStr = null;

        SymmetricKey sessionKey = null;
        SymmetricKey masterKey = null;

        if (keyNickName == null) {
            keyNameStr = this.getKeyName(keyInfo);
        } else {
            keyNameStr = keyNickName;
        }

        byte[] context = null;

        if (nistSP800_108KdfUseCuidAsKdd == true) {
            context = xCUID;
        } else {
            context = xKDD;
        }

        if ((keyInfo[0] == 0x1 && keyInfo[1] == 0x1 && keyNameStr.equals("#01#01")) ||
                (keyInfo[0] == -1 && keyNameStr.indexOf("#FF") != -1))

        {
            /* default manufacturers key */

            String finalKeyType = keyType;

            SymmetricKey devSymKey = returnDeveloperSymKey(token, finalKeyType, keySet, devKeyArray);

            // Create the auth with is the same as enc, might need it later.
            if (keyType.equals(encType)) {
                returnDeveloperSymKey(token, authType, keySet, devKeyArray);
            }

            if (noDerive == true) {
                sessionKey = devSymKey;
            } else {
                sessionKey = deriveKey_SCP01(token, devSymKey, host_challenge, card_challenge);
            }

        } else {

            SymmetricKey devKey = null;
            CMS.debug(method + "In master key mode.");

            masterKey = getSymKeyByName(token, keyNameStr);

            if (NistSP800_108KDF.useThisKDF(nistSP800_108KdfOnKeyVersion, keyInfo[1])) {
                CMS.debug(method + " ComputeSessionKey NistSP800_108KDF code: Using NIST SP800-108 KDF.");

                NistSP800_108KDF nistKDF = new NistSP800_108KDF(this);

                Map<String, SymmetricKey> keys = null;
                try {
                    keys = nistKDF.computeCardKeys(masterKey, context, token);
                } catch (EBaseException e) {
                    CMS.debug(method + "Can't compute card keys! " + e);
                    throw e;
                }

                devKey = keys.get(keyType);

            } else {
                StandardKDF standardKDF = new StandardKDF(this);
                CMS.debug(method + " ComputeSessionKey NistSP800_108KDF code: Using original KDF.");
                byte[] data = KDF.getDiversificationData(context, keyType);
                devKey = standardKDF.computeCardKey(masterKey, data, token, PROTOCOL_ONE);
            }

            if (noDerive == true) {
                sessionKey = devKey;
            } else {
                sessionKey = deriveKey_SCP01(token, devKey, host_challenge, card_challenge);
            }
        }

        return sessionKey;
    }

    private SymmetricKey deriveKey_SCP01(CryptoToken token, SymmetricKey cardKey, byte[] host_challenge,
            byte[] card_challenge)
            throws EBaseException {
        String method = "SecureChannelProtocol.deriveKey_SCP01:";
        CMS.debug(method + "entering..");

        if (cardKey == null || token == null) {
            throw new EBaseException(method + " Invalid input data!");
        }

        byte[] derivationData = new byte[KEYLENGTH];

        SymmetricKey derivedKey = null;

        for (int i = 0; i < 4; i++)
        {
            derivationData[i] = card_challenge[i + 4];
            derivationData[i + 4] = host_challenge[i];
            derivationData[i + 8] = card_challenge[i];
            derivationData[i + 12] = host_challenge[i + 4];
        }

        SymmetricKeyDeriver encryptDes3;
        byte[] encrypted = null;
        try {
            encryptDes3 = token.getSymmetricKeyDeriver();

            encryptDes3.initDerive(
                    cardKey, /* PKCS11Constants.CKM_DES3_ECB_ENCRYPT_DATA */4354L, derivationData, null,
                    PKCS11Constants.CKM_DES3_ECB, PKCS11Constants.CKA_DERIVE, 16);

            try {
                derivedKey = encryptDes3.derive();
            } catch (TokenException e) {
                CMS.debug(method + "Unable to derive the key with the proper mechanism!" + e);
                CMS.debug(method + "Now try this the old fashioned way");

                encrypted = computeDes3EcbEncryption(cardKey, token.getName(), derivationData);
                byte[] parityEncrypted = KDF.getDesParity(encrypted);
                CMS.debug(method + "encryption completed");

                derivedKey = this.unwrapSymKeyOnToken(token, null, parityEncrypted, false);
            }

        } catch (TokenException | InvalidKeyException | EBaseException e) {
            CMS.debug(method + "Unable to derive the key with the proper mechanism!");
            throw new EBaseException(e);
        }

        return derivedKey;
    }

    public SymmetricKey getSharedSecretKey(CryptoToken token) throws EBaseException {

        String method = "SecureChannelProtocol.getSharedSecretKey:";
        CMS.debug(method + "entering: transportKey: " + transportKey);

        CryptoToken finalToken = token;
        CryptoToken internalToken = null;
        if (token == null) {

            CMS.debug(method + " No token provided assume internal ");
            CryptoManager cm = null;
            try {
                cm = CryptoManager.getInstance();
                internalToken = returnTokenByName("internal", cm);
                finalToken = internalToken;
            } catch (NotInitializedException e) {
                CMS.debug(method + " " + e);
                throw new EBaseException(e);

            } catch (NoSuchTokenException e) {
                CMS.debug(method + " " + e);
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

    private String getKeyName(byte[] keyVersion) {
        String method = "SecureChannelProtocol.getKeyName:";
        CMS.debug(method + " Entering...");
        String keyName = null;

        if (keyVersion == null || keyVersion.length != 2) {
            return null;
        }

        SecureChannelProtocol.debugByteArray(keyVersion, "keyVersion array:");
        keyName = "#" + String.format("%02X", keyVersion[0]) + "#" + String.format("%02X", keyVersion[1]);

        CMS.debug(method + " returning: " + keyName);

        return keyName;
    }

    public static String getSharedSecretKeyName(String name) throws EBaseException {

        String method = "SecureChannelProtocol.getSharedSecretKeyName:";
        CMS.debug(method + " Entering...");

        if (name != null && SecureChannelProtocol.sharedSecretKeyName == null) {
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
    private SymmetricKey returnDeveloperSymKey(CryptoToken token, String keyType, String keySet, byte[] inputKeyArray)
            throws EBaseException {

        SymmetricKey devKey = null;

        String method = "SecureChannelProtocol.returnDeveloperSymKey:";

        String devKeyName = keySet + "-" + keyType + "Key";
        CMS.debug(method + " entering.. searching for key: " + devKeyName);

        if (token == null || keyType == null || keySet == null) {
            throw new EBaseException(method + "Invalid input data!");
        }

        try {
            CMS.debug(method + " requested token: " + token.getName());
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

            CMS.debug(method + " inputKeyArray.length: " + inputLen);

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

            SecureChannelProtocol.debugByteArray(des3InputKey, "Developer key to import: " + keyType + ": ");

            devKey = unwrapSymKeyOnToken(token, des3InputKey, true);
            devKey.setNickName(devKeyName);
        } else {
            CMS.debug(method + " Found sym key: " + devKeyName);
        }
        return devKey;
    }

    public SymmetricKey unwrapSymKeyOnToken(CryptoToken token, SymmetricKey unwrappingKey, byte[] inputKeyArray,
            boolean isPerm)
            throws EBaseException {

        String method = "SecureChannelProtocol.unwrapSymKeyOnToken:";
        CMS.debug(method + "Entering...");
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

        if (inputKeyArray.length == DES2_LENGTH) {
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
                wrappedKey = encryptor.doFinal(finalKeyArray);
            } else {
                wrappedKey = encryptor.doFinal(inputKeyArray);
            }

            CMS.debug(method + " done enrypting data");

            // SecureChannelProtocol.debugByteArray(wrappedKey, " encrypted key");

            KeyWrapper keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.DES3_ECB);
            keyWrap.initUnwrap(encUnwrapKey, null);

            if (isPerm == true) {
                unwrapped = keyWrap.unwrapSymmetricPerm(wrappedKey,
                        SymmetricKey.DES3, 0);
            } else {
                unwrapped = keyWrap.unwrapSymmetric(wrappedKey, SymmetricKey.DES3, 0);
            }

        } catch (Exception e) {
            CMS.debug(method + " " + e);
            throw new EBaseException(e);
        } finally {
            if (finalKeyArray != null) {
                Arrays.fill(finalKeyArray, (byte) 0);
            }
        }

        CMS.debug(method + "Returning symkey: " + unwrapped);

        return unwrapped;
    }

    public SymmetricKey unwrapWrappedSymKeyOnToken(CryptoToken token, SymmetricKey unwrappingKey, byte[] inputKeyArray,
            boolean isPerm)
            throws EBaseException {

        String method = "SecureChannelProtocol.unwrapWrappedSymKeyOnToken:";
        CMS.debug(method + "Entering...");
        SymmetricKey unwrapped = null;
        SymmetricKey finalUnwrapped = null;

        if (token == null || unwrappingKey == null) {
            throw new EBaseException(method + "Invalid input!");
        }

        if (inputKeyArray == null || (inputKeyArray.length != DES3_LENGTH && inputKeyArray.length != DES2_LENGTH)) {
            throw new EBaseException(method + "No raw array to use to create key!");
        }

        try {
            KeyWrapper keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.DES3_ECB);
            keyWrap.initUnwrap(unwrappingKey, null);

            if (isPerm) {
                unwrapped = keyWrap.unwrapSymmetricPerm(inputKeyArray,
                        SymmetricKey.DES3, SymmetricKey.Usage.UNWRAP, inputKeyArray.length);
            } else {
                unwrapped = keyWrap.unwrapSymmetric(inputKeyArray, SymmetricKey.DES3, SymmetricKey.Usage.UNWRAP,
                        inputKeyArray.length);
            }

            finalUnwrapped = makeDes3KeyDerivedFromDes2(unwrapped, token.getName());

        } catch (Exception e) {
            CMS.debug(method + " " + e);
            throw new EBaseException(e);
        }

        CMS.debug(method + "Returning symkey: " + unwrapped);

        return finalUnwrapped;
    }

    public SymmetricKey unwrapSymKeyOnToken(CryptoToken token, byte[] inputKeyArray, boolean isPerm)
            throws EBaseException {

        String method = "SecureChannelProtocol.unwrapSymKeyOnToken:";
        CMS.debug(method + "Entering...");
        SymmetricKey unwrapped = null;

        if (token == null) {
            throw new EBaseException(method + "Invalide crypto token!");
        }

        if (inputKeyArray == null || (inputKeyArray.length != DES3_LENGTH && inputKeyArray.length != DES2_LENGTH)) {
            throw new EBaseException(method + "No raw array to use to create key!");
        }

        SymmetricKey transport = getSharedSecretKey(token);
        unwrapped = this.unwrapSymKeyOnToken(token, transport, inputKeyArray, isPerm);

        CMS.debug(method + "Returning symkey: " + unwrapped);

        return unwrapped;
    }

    public static SymmetricKey getSymKeyByName(CryptoToken token, String name) throws EBaseException {

        String method = "SecureChannelProtocol.getSymKeyByName:";
        if (token == null || name == null) {
            throw new EBaseException(method + "Invalid input data!");
        }
        SymmetricKey[] keys;

        CMS.debug(method + "Searching for sym key: " + name);
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
                    CMS.debug(method + "Found key: " + name);
                    return cur;
                }
            }
        }

        CMS.debug(method + " Sym Key not found.");
        return null;
    }

    public CryptoToken returnTokenByName(String name, CryptoManager manager) throws NoSuchTokenException {

        if (name == null || manager == null)
            throw new NoSuchTokenException();

        if (name.equals("internal") || name.equals("Internal KeyStorage Token")) {
            return manager.getInternalKeyStorageToken();
        } else {
            return manager.getTokenByName(name);
        }

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

        CMS.debug("About to dump array: " + message);

        if (array == null) {
            CMS.debug("Array to dump is empty!");
            return;
        }

        CMS.debug("################### ");

        String result = getHexString(array);
        CMS.debug(result);
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
            CMS.debug(method + " " + e);
            throw new EBaseException(e);

        }

        cryptoManager = cm;

        return cryptoManager;

    }

    public static byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
    }

    /* Generate 24 key, but with a DES2 key converted to DES3
       This needed to appease the server side keygen and the coollkey applet.
    */
    public SymmetricKey generateSymKey(String selectedToken) throws EBaseException {
        String method = "SecureChannelProtocol.generateSymKey:";

        CMS.debug(method + " entering , token: " + selectedToken);
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

        } catch (NoSuchAlgorithmException | TokenException | NoSuchTokenException | IllegalStateException
                | CharConversionException e) {
            CMS.debug(method + " " + e);
            throw new EBaseException(e);
        }

        return symKeyFinal;

    }

    public byte[] ecbEncrypt(SymmetricKey devKey, SymmetricKey symKey, String selectedToken) throws EBaseException {
        byte[] result = null;
        String method = "SecureChannelProtocol.ecbEncrypt:";
        CMS.debug(method + " Entering...");

        if (devKey == null || symKey == null || selectedToken == null) {
            throw new EBaseException(method + " Invalid input parameters.");
        }

        String devKeyToken = null;
        try {
            devKeyToken = symKey.getOwningToken().getName();
            CMS.debug(method + " symKey token: " + devKeyToken);
            CMS.debug(method + " devKey token: " + devKey.getOwningToken().getName());

        } catch (TokenException e) {
        }
        SymmetricKey des2 = this.extractDes2FromDes3(symKey, devKeyToken);

        result = this.wrapSessionKey(selectedToken, des2, devKey);

        // SecureChannelProtocol.debugByteArray(result, " Wrapped des2 key");

        return result;
    }

    /* Convenience routine to create a 3DES key from a 2DES key.
    This is done by taking the first 8 bytes of the 2DES key and copying it to the end, making
     a faux 3DES key. This is required due to applet requirements.
    */
    public SymmetricKey makeDes3KeyDerivedFromDes2(SymmetricKey des3Key, String selectedToken) throws EBaseException {
        SymmetricKey des3 = null;

        String method = "SecureChannelProtocol.makeDes3KeyDerivedFromDes2:";

        CMS.debug(method + " Entering ...");

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

            CMS.debug(method + " extracted8 key: " + extracted8);

            SymmetricKeyDeriver concat = token.getSymmetricKeyDeriver();
            concat.initDerive(
                    extracted16, extracted8, PKCS11Constants.CKM_CONCATENATE_BASE_AND_KEY, null, null,
                    PKCS11Constants.CKM_DES3_ECB, PKCS11Constants.CKA_DERIVE, 0);

            des3 = concat.derive();

        } catch (NoSuchTokenException | IllegalStateException | TokenException | InvalidKeyException e) {
            CMS.debug(method + " " + e);
            throw new EBaseException(e);
        }

        return des3;
    }

    public SymmetricKey extractDes2FromDes3(SymmetricKey baseKey, String selectedToken) throws EBaseException {
        String method = "SecureChannelProtocol.extractDes2FromDes3:";
        CMS.debug(method + " Entering: ");

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

        } catch (NoSuchTokenException | IllegalStateException | TokenException | InvalidKeyException e) {
            CMS.debug(method + " " + e);
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

        try {
            CryptoManager cm = this.getCryptoManger();
            CryptoToken token = returnTokenByName(tokenName, cm);

            keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.DES3_ECB);
            keyWrap.initWrap(wrapper, null);
            wrappedSessKeyData = keyWrap.wrap(sessionKey);
        } catch (NoSuchAlgorithmException | TokenException | InvalidKeyException | InvalidAlgorithmParameterException
                | NoSuchTokenException e) {
            CMS.debug(method + " " + e);
            throw new EBaseException(e);
        }

        CMS.debug(method + " About to return session key: " + wrappedSessKeyData);

        return wrappedSessKeyData;

    }

    public byte[] computeDes3EcbEncryption(SymmetricKey desKey, String selectedToken, byte[] input)
            throws EBaseException {

        String method = "SecureChannelProtocol.computeDes3EcbEncryption";
        byte[] output = null;

        if (desKey == null || selectedToken == null) {
            throw new EBaseException(method + " Invalid input data.");
        }

        try {
            CryptoManager cm = this.getCryptoManger();
            CryptoToken token = returnTokenByName(selectedToken, cm);
            CMS.debug("desKey: owning token: " + desKey.getOwningToken().getName());
            CMS.debug("desKey: current token: " + token.getName());
            Cipher encryptor = token.getCipherContext(EncryptionAlgorithm.DES3_ECB);
            CMS.debug("got encryptor");
            encryptor.initEncrypt(desKey);
            CMS.debug("done initEncrypt");
            output = encryptor.doFinal(input);
            CMS.debug("done doFinal " + output);

            // SecureChannelProtocol.debugByteArray(output, "Encrypted data:");
        } catch (EBaseException | NoSuchTokenException | NoSuchAlgorithmException | TokenException
                | InvalidKeyException | InvalidAlgorithmParameterException |
                IllegalStateException | IllegalBlockSizeException | BadPaddingException e) {

            CMS.debug(method + e);
            throw new EBaseException(method + e);
        }
        CMS.debug("returning encrypted output.");
        // SecureChannelProtocol.debugByteArray(output, "Encrypted data before leaving:");

        return output;
    }

    public byte[] computeKeyCheck(SymmetricKey desKey, String selectedToken) throws EBaseException {

        String method = "SecureChannelProtocol.computeKeyCheck:";

        CMS.debug(method + " Entering...");

        byte[] input = new byte[EIGHT_BYTES];
        byte[] finalOutput = new byte[3];

        if (desKey == null || selectedToken == null) {
            throw new EBaseException(method + " Invalid input data.");
        }

        byte[] output = null;
        String keysToken = null;
        try {
            keysToken = desKey.getOwningToken().getName();
        } catch (TokenException e1) {
            throw new EBaseException(e1 + " Can't get owning token for key/");
        }

        try {
            output = computeDes3EcbEncryption(desKey, keysToken, input);
        } catch (EBaseException e) {
            CMS.debug(method + e);
            throw e;

        }

        //Get the 3 bytes needed
        System.arraycopy(output, 0, finalOutput, 0, 3);

        SecureChannelProtocol.debugByteArray(finalOutput, "Calculated KeyCheck Value:");

        return finalOutput;
    }

    public byte[] computeMAC_SCP01(SymmetricKey symKey, byte[] input, byte[] icv, String selectedToken)
            throws EBaseException {
        byte[] output = null;
        byte[] result = null;

        String method = "SecureChannelProtocol.computeMAC_SCP01:";

        CMS.debug(method + " Entering...");

        if (symKey == null || input == null || icv == null || icv.length != EIGHT_BYTES) {
            throw new EBaseException(method + " invalid input data!");
        }
        int inputLen = input.length;

        byte[] macPad = new byte[8];
        macPad[0] = (byte) 0x80;

        CryptoToken token = null;

        try {

            CryptoManager cm = this.getCryptoManger();
            token = returnTokenByName(selectedToken, cm);

            Cipher cipher = token.getCipherContext(EncryptionAlgorithm.DES3_ECB);
            cipher.initEncrypt(symKey);

            result = new byte[EIGHT_BYTES];
            System.arraycopy(icv, 0, result, 0, EIGHT_BYTES);

            /* Process whole blocks */
            int inputOffset = 0;
            while (inputLen >= 8)
            {
                for (int i = 0; i < 8; i++)
                {
                    //Xor implicitly converts bytes to ints, we convert answer back to byte.
                    byte a = (byte) (result[i] ^ input[inputOffset + i]);
                    result[i] = a;
                }

                byte[] ciphResult = cipher.update(result);

                if (ciphResult.length != result.length) {
                    throw new EBaseException(method + " Invalid cipher!");
                }

                System.arraycopy(ciphResult, 0, result, 0, EIGHT_BYTES);

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
                byte a = (byte) (result[i] ^ input[inputOffset + i]);
                result[i] = a;
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
                byte a = (byte) (result[i] ^ macPad[padOffset++]);
                result[i] = a;
                i++;
            }

            output = cipher.doFinal(result);

            if (output.length != result.length) {
                throw new EBaseException(method + " Invalid cipher!");
            }

        } catch (Exception e) {
            throw new EBaseException(method + " Cryptographic problem encountered! " + e.toString());
        }

        // SecureChannelProtocol.debugByteArray(output, method + " output: ");

        return output;
    }

    public byte[] diversifyKey(String tokenName,
            String newTokenName,
            String oldMasterKeyName,
            String newMasterKeyName,
            byte[] oldKeyInfo,
            byte[] newKeyInfo,
            byte nistSP800_108KdfOnKeyVersion,
            boolean nistSP800_108KdfUseCuidAsKdd,
            byte[] CUIDValue,
            byte[] KDD,
            byte[] kekKeyArray,
            String useSoftToken, String keySet, byte protocol) throws EBaseException {

        String method = "SecureChannelProtocol.diversifyKey:";

        CMS.debug(method + " Entering ... newTokenName: " + newTokenName);

        SymmetricKey masterKey = null;
        SymmetricKey oldMasterKey = null;

        byte[] KDCenc = null;
        byte[] KDCmac = null;
        byte[] KDCkek = null;

        SymmetricKey old_mac_sym_key = null;
        SymmetricKey old_enc_sym_key = null;
        SymmetricKey old_kek_sym_key = null;

        SymmetricKey encKey = null;
        SymmetricKey macKey = null;
        SymmetricKey kekKey = null;

        // The final answer
        byte[] output = null;

        if (oldMasterKeyName == null || oldKeyInfo == null || newKeyInfo == null
                || keySet == null) {
            throw new EBaseException(method + "Invalid input!");
        }

        if (oldKeyInfo.length < 2 || newKeyInfo.length < 2) {
            throw new EBaseException(method + " Invalid input length for keyinfo versions.");
        }

        String fullNewMasterKeyName = getFullMasterKeyName(newMasterKeyName);
        String fullOldMasterKeyName = getFullMasterKeyName(oldMasterKeyName);

        CryptoManager cm = null;
        CryptoToken token = null;
        CryptoToken newToken = null;
        try {
            cm = CryptoManager.getInstance();
            token = returnTokenByName(tokenName, cm);
            if (newTokenName != null) {
                newToken = returnTokenByName(newTokenName, cm);
            }
        } catch (NotInitializedException e) {
            CMS.debug(method + " " + e);
            throw new EBaseException(e);

        } catch (NoSuchTokenException e) {
            CMS.debug(method + " " + e);
            throw new EBaseException(e);
        }

        try {
            if (newToken != null) {
                masterKey = getSymKeyByName(newToken, fullNewMasterKeyName);
            }
            oldMasterKey = getSymKeyByName(token, fullOldMasterKeyName);
        } catch (EBaseException e) {
            masterKey = null;
            CMS.debug(method + " Master key is null, possibly ok in moving from keyset 2 to 1");

            if (oldMasterKey == null) {
                throw new EBaseException(method + " Can't retrieve old master key!");
            }
        }

        SecureChannelProtocol.debugByteArray(oldKeyInfo, " oldKeyInfo: ");
        SecureChannelProtocol.debugByteArray(newKeyInfo, " newKeyInfo: ");

        byte oldKeyVersion = oldKeyInfo[0];
        byte newKeyVersion = newKeyInfo[0];

        byte[] context = null;

        if (nistSP800_108KdfUseCuidAsKdd == true) {
            context = CUIDValue;
        } else {
            context = KDD;
        }

        if (context == null) {
            throw new EBaseException(method + "Invalid token id information included!");
        }

        // We may need either or both of these

        StandardKDF standardKDF = new StandardKDF(this);
        NistSP800_108KDF nistKDF = new NistSP800_108KDF(this);

        KDCenc = KDF.getDiversificationData(KDD, SecureChannelProtocol.encType);
        KDCmac = KDF.getDiversificationData(KDD, SecureChannelProtocol.macType);
        KDCkek = KDF.getDiversificationData(KDD, SecureChannelProtocol.kekType);

        if (protocol == PROTOCOL_ONE) {
            if (checkForDeveloperKeySet(oldMasterKeyName) == true) {
                CMS.debug(method + " Developer key set case: ");
            } else {
                CMS.debug(method + " Not Developer key set case: ");

                if (NistSP800_108KDF.useThisKDF(nistSP800_108KdfOnKeyVersion, oldKeyVersion)) {
                    CMS.debug(method + " NistSP800_108KDF code: Using NIST SP800-108 KDF.");

                    Map<String, SymmetricKey> keys = null;
                    try {
                        keys = nistKDF.computeCardKeys(oldMasterKey, context, token);
                    } catch (EBaseException e) {
                        CMS.debug(method + "Can't compute card keys! " + e);
                        throw e;
                    }

                    old_enc_sym_key = keys.get(SecureChannelProtocol.encType);
                    old_mac_sym_key = keys.get(SecureChannelProtocol.macType);
                    old_kek_sym_key = keys.get(SecureChannelProtocol.kekType);

                    if (old_enc_sym_key == null || old_mac_sym_key == null || old_kek_sym_key == null) {
                        throw new EBaseException(method + " Can't derive session keys with Nist KDF.");
                    }

                } else {
                    CMS.debug(method + " ComputeSessionKey NistSP800_108KDF code: Using original KDF.");

                    old_kek_sym_key = standardKDF.computeCardKey(oldMasterKey, KDCkek, token, PROTOCOL_ONE);
                }

            }

            /* special case #01#01 */
            if (fullNewMasterKeyName != null && fullNewMasterKeyName.equals("#01#01"))
            {
                CMS.debug(method + " Special case dev key set for DiversifyKey!");

                encKey = returnDeveloperSymKey(newToken, SecureChannelProtocol.encType, keySet, null);
                macKey = returnDeveloperSymKey(newToken, SecureChannelProtocol.macType, keySet, null);
                kekKey = returnDeveloperSymKey(newToken, SecureChannelProtocol.kekType, keySet, null);
            } else {
                CMS.debug(method + " Compute card key on token case ! For new key version");

                if (NistSP800_108KDF.useThisKDF(nistSP800_108KdfOnKeyVersion, newKeyVersion)) {
                    CMS.debug(method + " NistSP800_108KDF code: Using NIST SP800-108 KDF. For new key version.");

                    Map<String, SymmetricKey> keys = null;
                    try {
                        keys = nistKDF.computeCardKeys(masterKey, context, newToken);
                    } catch (EBaseException e) {
                        CMS.debug(method + "Can't compute card keys! For new key version. " + e);
                        throw e;
                    }

                    encKey = keys.get(SecureChannelProtocol.encType);
                    macKey = keys.get(SecureChannelProtocol.macType);
                    kekKey = keys.get(SecureChannelProtocol.kekType);

                } else {
                    CMS.debug(method
                            + " ComputeSessionKey NistSP800_108KDF code: Using original KDF. For new key version.");

                    encKey = standardKDF.computeCardKeyOnToken(masterKey, KDCenc, protocol);
                    macKey = standardKDF.computeCardKeyOnToken(masterKey, KDCmac, protocol);
                    kekKey = standardKDF.computeCardKeyOnToken(masterKey, KDCkek, protocol);
                }

                if (encKey == null || macKey == null || kekKey == null) {
                    throw new EBaseException(method
                            + " Can't derive session keys with selected KDF. For new key version.");
                }

            }

        } else if (protocol == PROTOCOL_TWO) {
            throw new EBaseException(method + " SCP 02 not yet supported here.");
        } else {
            throw new EBaseException(method + " Unsupported protocol verison.");
        }

        boolean showKeysForDebug = false;

        if (showKeysForDebug == true) {
            try {
                SecureChannelProtocol.debugByteArray(encKey.getKeyData(), "DiversifyKey: new encKey: ");
                SecureChannelProtocol.debugByteArray(macKey.getKeyData(), "DiversifyKey: new macKey:");
                SecureChannelProtocol.debugByteArray(kekKey.getKeyData(), "DiversifyKey: new kekKey");
            } catch (NotExtractableException e) {
                CMS.debug(method + " Can not display debugging info for key");
            }
        }

        if (old_kek_sym_key != null) {

            CMS.debug(method + " old kek sym key is not null");
            output = createKeySetDataWithSymKeys(newKeyVersion, (byte[]) null,
                    old_kek_sym_key,
                    encKey,
                    macKey,
                    kekKey,
                    protocol, tokenName);

        } else {

            CMS.debug(method + " old kek sym key is null");
            old_kek_sym_key = returnDeveloperSymKey(token, SecureChannelProtocol.kekType, keySet, kekKeyArray);
            output = createKeySetDataWithSymKeys(newKeyVersion, (byte[]) null,
                    old_kek_sym_key,
                    encKey,
                    macKey,
                    kekKey,
                    protocol, tokenName);

        }

        return output;
    }

    private byte[] createKeySetDataWithSymKeys(byte newKeyVersion, byte[] old_kek_key_array,
            SymmetricKey old_kek_sym_key,
            SymmetricKey encKey, SymmetricKey macKey, SymmetricKey kekKey, byte protocol, String tokenName)
            throws EBaseException {

        SymmetricKey wrappingKey = null;

        String method = "SecureChannelProtocol.createKeySetDataWithSymKeys:";

        byte alg = (byte) 0x81;

        byte[] output = null;

        if (encKey == null || macKey == null || kekKey == null || tokenName == null) {
            throw new EBaseException(method + " Invalid input data!");
        }

        CryptoManager cm = null;
        CryptoToken token = null;
        try {
            cm = CryptoManager.getInstance();
            token = returnTokenByName(tokenName, cm);
        } catch (NotInitializedException e) {
            CMS.debug(method + " " + e);
            throw new EBaseException(e);

        } catch (NoSuchTokenException e) {
            CMS.debug(method + " " + e);
            throw new EBaseException(e);
        }

        SymmetricKey encKey16 = null;
        SymmetricKey macKey16 = null;
        SymmetricKey kekKey16 = null;

        byte[] encrypted_enc_key = null;
        byte[] encrypted_mac_key = null;
        byte[] encrypted_kek_key = null;

        byte[] keycheck_enc_key = null;
        byte[] keycheck_mac_key = null;
        byte[] keycheck_kek_key = null;

        if (protocol == PROTOCOL_ONE) {
            if (old_kek_sym_key == null) {
                CMS.debug(method + " Using old kek key array.");
                wrappingKey = unwrapSymKeyOnToken(token, old_kek_key_array, false);
            } else {
                CMS.debug(method + " Using input old key key sym key.");
                wrappingKey = old_kek_sym_key;
            }

            alg = (byte) 0x81;
            encKey16 = extractDes2FromDes3(encKey, tokenName);
            macKey16 = extractDes2FromDes3(macKey, tokenName);
            kekKey16 = extractDes2FromDes3(kekKey, tokenName);

            encrypted_enc_key = this.wrapSessionKey(tokenName, encKey16, wrappingKey);
            encrypted_mac_key = this.wrapSessionKey(tokenName, macKey16, wrappingKey);
            encrypted_kek_key = this.wrapSessionKey(tokenName, kekKey16, wrappingKey);

            keycheck_enc_key = this.computeKeyCheck(encKey, tokenName);
            keycheck_mac_key = this.computeKeyCheck(macKey, tokenName);
            keycheck_kek_key = this.computeKeyCheck(kekKey, tokenName);

            debugByteArray(keycheck_enc_key, " Keycheck enc key: ");
            debugByteArray(keycheck_mac_key, " Keycheck mac key: ");
            debugByteArray(keycheck_kek_key, " KeyCheck kek key: ");

        } else if (protocol == PROTOCOL_TWO) {
            alg = (byte) 0x80;
            throw new EBaseException(method + " SCP 02 not yet implemented!");
        } else {
            throw new EBaseException(method + " Invalid SCP version requested!");
        }

        // Compose the final key set data byte array

        byte[] b1 = new byte[] { alg, 0x10 };
        byte[] b2 = new byte[] { 0x3 };

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        try {
            outputStream.write(newKeyVersion);
            outputStream.write(b1);
            outputStream.write(encrypted_enc_key);
            outputStream.write(b2);
            outputStream.write(keycheck_enc_key);

            outputStream.write(b1);
            outputStream.write(encrypted_mac_key);
            outputStream.write(b2);
            outputStream.write(keycheck_mac_key);

            outputStream.write(b1);
            outputStream.write(encrypted_kek_key);
            outputStream.write(b2);
            outputStream.write(keycheck_kek_key);

            output = outputStream.toByteArray();

        } catch (IOException e) {
            throw new EBaseException(method + " Can't compose final output byte array!");
        }

        SecureChannelProtocol.debugByteArray(output, " Final output to createKeySetData: ");

        return output;
    }

    private String getFullMasterKeyName(String masterKeyName)
    {
        if (masterKeyName == null)
        {
            return null;
        }

        String fullMasterKeyName = null;

        fullMasterKeyName = "";

        if (masterKeyName.length() > 0) {
            fullMasterKeyName += masterKeyName;
        }

        return fullMasterKeyName;
    }

    private boolean checkForDeveloperKeySet(String keyInfo)
    {
        if (keyInfo == null)
            return true;

        //SCP01 or SCP02
        if (keyInfo.equals("#01#01") || keyInfo.equals("#FF#01"))
            return true;

        //SCP02
        if (keyInfo.equals("#01#02") || keyInfo.equals("#FF#02"))
            return true;

        return false;
    }

    public static void setDefaultPrefix(String masterkeyPrefix) {
        if (SecureChannelProtocol.masterKeyPrefix == null) {
            SecureChannelProtocol.masterKeyPrefix = masterkeyPrefix;
        }
    }

    public byte[] encryptData(String selectedToken, String keyNickName, byte[] data, byte[] keyInfo,
            byte nistSP800_108KdfOnKeyVersion, boolean nistSP800_108KdfUseCuidAsKdd, byte[] xCUID, byte[] xKDD,
            byte[] kekKeyArray, String useSoftToken_s, String keySet) throws EBaseException {

        String method = "SecureChannelProtocol.encryptData:";

        CMS.debug(method + " Entering ....");

        String transportKeyName = SecureChannelProtocol.getSharedSecretKeyName(null);

        if (keyInfo == null || keySet == null || (keyInfo == null || keyInfo.length < 2)) {
            throw new EBaseException(method + "Invalid input!");
        }

        if (xCUID == null || xCUID.length <= 0) {
            throw new EBaseException(method + "CUID invalid size!");
        }

        if (xKDD == null || xKDD.length != NistSP800_108KDF.KDD_SIZE_BYTES) {
            throw new EBaseException(method + "KDD invalid size!");
        }

        SymmetricKey kekKey = computeSessionKey_SCP01(kekType, selectedToken, keyNickName, null,
                null, keyInfo, nistSP800_108KdfOnKeyVersion, nistSP800_108KdfUseCuidAsKdd, xCUID, xKDD,
                kekKeyArray, useSoftToken_s, keySet, transportKeyName);

        byte[] output = computeDes3EcbEncryption(kekKey, selectedToken, data);

        // debugByteArray(output, " encryptData: Output: ");

        return output;
    }

}
