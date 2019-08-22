package com.netscape.cms.servlet.tks;

import com.netscape.certsrv.base.EBaseException;

public class KDF {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KDF.class);

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
            /* E */0xf1, 0xf2, 0xf4, 0xf7, 0xf8, 0xfb, 0xfd, 0xfe, };

    //Add the emv diversification method, used in SCP03 g&d card.
    public static byte[] getDiversificationData_EMV(byte[] context, String type) throws EBaseException {

        String method = "KDF.getDiversificationData_EMV:";

        logger.debug(method + " entering ...");

        if (context == null || type == null) {
            throw new EBaseException(method + "Invalid input parameters!");
        }

        byte[] KDC = new byte[SecureChannelProtocol.DES2_LENGTH];

        KDC[0] = context[4 + 0];
        KDC[1] = context[4 + 1];
        KDC[2] = context[4 + 2];
        KDC[3] = context[4 + 3];
        KDC[4] = context[4 + 4];
        KDC[5] = context[4 + 5];
        KDC[6] = (byte) 0xF0;

        KDC[7] = 0x1;

        KDC[8] = context[4 + 0];
        KDC[9] = context[4 + 1];
        KDC[10] = context[4 + 2];
        KDC[11] = context[4 +3];
        KDC[12] = context[4 + 4];
        KDC[13] = context[4 + 5];
        KDC[14] = (byte) 0x0f;

        KDC[15] = 0x1;

        if (type.equals(SecureChannelProtocol.encType))
            return KDC;

        KDC[7] = 0x02;
        KDC[15] = 0x02;
        if (type.equals(SecureChannelProtocol.macType))
            return KDC;

        KDC[7] = 0x03;
        KDC[15] = 0x03;
        if (type.equals(SecureChannelProtocol.kekType))
            return KDC;

        KDC[7] = 0x04;
        KDC[15] = 0x04;
        if (type.equals(SecureChannelProtocol.rmacType))
            return KDC;
        return KDC;

    }

    //Standard visa2 diversification method
    public static byte[] getDiversificationData_VISA2(byte[] context, String type) throws EBaseException {

        String method = "KDF.getDiversificationData_VISA2:";

        logger.debug(method + " entering ...");

        if (context == null || type == null) {
            throw new EBaseException(method + "Invalid input parameters!");
        }

        byte[] KDC = new byte[SecureChannelProtocol.DES2_LENGTH];

        //      BYTE *lastTwoBytesOfAID     = (BYTE *)cuidValue;
        //      BYTE *ICFabricationDate         = (BYTE *)cuidValue + 2;
        //      BYTE *ICSerialNumber        = (BYTE *)cuidValue + 4
        //      BYTE *ICBatchIdentifier         = (BYTE *)cuidValue + 8;

        // Last 2 bytes of AID
        KDC[0] = context[0];
        KDC[1] = context[1];
        KDC[2] = context[4 + 0];
        KDC[3] = context[4 + 1];
        KDC[4] = context[4 + 2];
        KDC[5] = context[4 + 3];
        KDC[6] = (byte) 0xF0;
        KDC[7] = 0x01;
        KDC[8] = context[0];
        KDC[9] = context[1];
        KDC[10] = context[4 + 0];
        KDC[11] = context[4 + 1];
        KDC[12] = context[4 + 2];
        KDC[13] = context[4 + 3];
        KDC[14] = 0x0F;
        KDC[15] = 0x01;

        if (type.equals(SecureChannelProtocol.encType))
            return KDC;

        KDC[6] = (byte) 0xF0;
        KDC[7] = 0x02;
        KDC[14] = 0x0F;
        KDC[15] = 0x02;
        if (type.equals(SecureChannelProtocol.macType))
            return KDC;

        KDC[6] = (byte) 0xF0;
        KDC[7] = 0x03;
        KDC[14] = 0x0F;
        KDC[15] = 0x03;
        if (type.equals(SecureChannelProtocol.kekType))
            return KDC;

        return KDC;

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

}
