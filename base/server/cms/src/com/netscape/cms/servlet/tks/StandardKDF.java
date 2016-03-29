package com.netscape.cms.servlet.tks;

import java.security.InvalidKeyException;

import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.SymmetricKeyDeriver;
import org.mozilla.jss.crypto.TokenException;

import sun.security.pkcs11.wrapper.PKCS11Constants;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;

public class StandardKDF extends KDF {
    SecureChannelProtocol protocol = null;

    StandardKDF(SecureChannelProtocol protocol) {
        this.protocol = protocol;
    }

    public SymmetricKey computeCardKey(SymmetricKey masterKey, byte[] derivationData, CryptoToken token, int protocol)
            throws EBaseException {

        String method = "StandardKDF.computeCardKeys:";

        SymmetricKey result = null;

        CMS.debug(method + " entering ...");

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

                CMS.debug(method + "Unable to derive the key with the proper mechanism!");
                CMS.debug(method + "Now try this the old fashioned way");

                byte[] encrypted = this.protocol.computeDes3EcbEncryption(masterKey, token.getName(), derivationData);
                byte[] parityEncrypted = KDF.getDesParity(encrypted);
                CMS.debug(method + "done computeDes3EcbEncryptiong");
                derivedKey = this.protocol.unwrapSymKeyOnToken(token, null,
                        parityEncrypted, false);

                // The key this way is aleady des3, return

                return derivedKey;
            }


            CMS.debug(method + " derived card key first 16 :" + derivedKey);

            //  byte[] extracted = derivedKey.getEncoded();
            // SecureChannelProtocol.debugByteArray(extracted, " Derived key 16.");

            CMS.debug(method + " derivedKey 16: owning token: " + derivedKey.getOwningToken().getName());

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
           CMS.debug(method + " final 24 byte key: " + result);
           // byte [] extracted24Bytes = result.getEncoded();
           // SecureChannelProtocol.debugByteArray(extracted24Bytes, " Derived key 24.");

        } catch (TokenException | InvalidKeyException e) {
            CMS.debug(method + "Unable to derive the key with the proper mechanism!");
            throw new EBaseException(e);
        }

        return result;

    }

    public SymmetricKey computeCardKeyOnSoftToken(SymmetricKey masterKey, byte[] data, int protocol)
            throws EBaseException {
        String method = "StandardKDF.computeCardKeys:";

        CMS.debug(method + " entering...");

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
