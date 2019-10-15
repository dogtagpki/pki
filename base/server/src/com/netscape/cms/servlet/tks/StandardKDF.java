package com.netscape.cms.servlet.tks;

import java.security.InvalidKeyException;

import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.SymmetricKeyDeriver;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.pkcs11.PKCS11Constants;

import com.netscape.certsrv.base.EBaseException;

public class StandardKDF extends KDF {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(StandardKDF.class);

    SecureChannelProtocol protocol = null;

    StandardKDF(SecureChannelProtocol protocol) {
        this.protocol = protocol;
    }

    // For the scp03 g&d smart cafe, the dev keys must start out as DES3 keys
    // but then this routine must return the AES version of the key

    public SymmetricKey computeCardKey_SCP03_WithDES3(SymmetricKey masterKey, byte[] derivationData, CryptoToken token)
            throws EBaseException {

        String method = "StandardKDF.computeCardKey_SCP03_WithDES3:";

        logger.debug(method + " entering ...");

        if (masterKey == null || token == null
                || derivationData == null || ((derivationData.length != SecureChannelProtocol.AES_128_BYTES) &&
                        (derivationData.length != SecureChannelProtocol.AES_192_BYTES) &&
                (derivationData.length != SecureChannelProtocol.AES_256_BYTES))) {

            logger.error(method + " Invalid input parameters!");

            throw new EBaseException(method + " Invalid input parameters!");
        }

        //Now the new key data is the derivation data encrypted with DESS3

        byte[] encrypted;
        try {
            encrypted = this.protocol.computeDes3EcbEncryption(masterKey, token.getName(), derivationData);
        } catch (TokenException e) {
           throw new EBaseException(method + "Can't derive key data!");
        }
        //SecureChannelProtocol.debugByteArray(encrypted, "calculated key: ");

        return this.protocol.unwrapAESSymKeyOnToken(token, encrypted, false);

    }
    public SymmetricKey computeCardKey(SymmetricKey masterKey, byte[] derivationData, CryptoToken token, int protocol)
            throws EBaseException {

        String method = "StandardKDF.computeCardKeys:";

        SymmetricKey result = null;

        logger.debug(method + " entering ...");

        if (masterKey == null || derivationData == null
                || derivationData.length != SecureChannelProtocol.DES2_LENGTH || token == null) {

            throw new EBaseException(method + " Invlalid input parameters!");
        }

        SymmetricKeyDeriver encryptDes3;
        try {

            encryptDes3 = token.getSymmetricKeyDeriver();

            encryptDes3.initDerive(
                    masterKey, /* PKCS11Constants.CKM_DES3_ECB_ENCRYPT_DATA */4354L, derivationData, null,
                    PKCS11Constants.CKM_DES3_ECB, PKCS11Constants.CKA_DERIVE, 16);


            SymmetricKey derivedKey = null;

            try {
                derivedKey = encryptDes3.derive();
            } catch (TokenException e) {

                logger.error(method + "Unable to derive the key with the proper mechanism!");
                logger.warn(method + "Now try this the old fashioned way");

                byte[] encrypted = this.protocol.computeDes3EcbEncryption(masterKey, token.getName(), derivationData);
                //SecureChannelProtocol.debugByteArray(encrypted, "calculated key: ");
              //  byte[] parityEncrypted = KDF.getDesParity(encrypted);
                logger.debug(method + "done computeDes3EcbEncryptiong");

                derivedKey = this.protocol.unwrapSymKeyOnToken(token, null,
                        encrypted, false,SymmetricKey.DES3);

                // The key this way is already final, return

                return derivedKey;
            }


            logger.debug(method + " derived card key first 16 :" + derivedKey);

            //  byte[] extracted = derivedKey.getEncoded();
            // SecureChannelProtocol.debugByteArray(extracted, " Derived key 16.");

            logger.debug(method + " derivedKey 16: owning token: " + derivedKey.getOwningToken().getName());

            long bitPosition = 0;

            byte[] param = SecureChannelProtocol.longToBytes(bitPosition);

            SymmetricKeyDeriver extract8 = token.getSymmetricKeyDeriver();
            extract8.initDerive(
                               derivedKey, PKCS11Constants.CKM_EXTRACT_KEY_FROM_KEY,param,null,
                               PKCS11Constants.CKA_ENCRYPT, PKCS11Constants.CKA_DERIVE,8);


           SymmetricKey extracted8 = extract8.derive();
           // byte [] extracted8Bytes = extracted8.getEncoded();
           // SecureChannelProtocol.debugByteArray(extracted8Bytes, " Derived key 8.");


           SymmetricKeyDeriver concat = token.getSymmetricKeyDeriver();
           concat.initDerive(
                              derivedKey,extracted8, PKCS11Constants.CKM_CONCATENATE_BASE_AND_KEY,null,null,
                              PKCS11Constants.CKM_DES3_ECB, PKCS11Constants.CKA_DERIVE,0);

           result =  concat.derive();
           logger.debug(method + " final 24 byte key: " + result);
           // byte [] extracted24Bytes = result.getEncoded();
           // SecureChannelProtocol.debugByteArray(extracted24Bytes, " Derived key 24.");

        } catch (TokenException | InvalidKeyException e) {
            logger.error(method + "Unable to derive the key with the proper mechanism: " + e.getMessage(), e);
            throw new EBaseException(e);
        }

        return result;

    }

    public SymmetricKey computeCardKeyOnSoftToken(SymmetricKey masterKey, byte[] data, int protocol)
            throws EBaseException {
        String method = "StandardKDF.computeCardKeys:";

        logger.debug(method + " entering...");

        if (masterKey == null || data == null) {
            throw new EBaseException(method + " Invlalid input parameters!");
        }

        CryptoToken token = this.protocol.getCryptoManger().getInternalKeyStorageToken();

        return this.computeCardKey(masterKey, data, token, protocol);
    }

    public SymmetricKey computeCardKeyOnToken(SymmetricKey masterKey, byte[] data, int protocol) throws EBaseException {
        String method = "StandardKDF.computeCardKeys:";

        if (masterKey == null || data == null) {
            throw new EBaseException(method + " Invlalid input parameters!");
        }

        CryptoToken token = masterKey.getOwningToken();

        return this.computeCardKey(masterKey, data, token, protocol);
    }
}
