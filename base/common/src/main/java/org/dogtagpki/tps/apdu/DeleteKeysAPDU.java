package org.dogtagpki.tps.apdu;

/**
 * ** G&D 256 Key Rollover Support **
 */

import org.dogtagpki.tps.main.TPSBuffer;

public class DeleteKeysAPDU extends APDU {

    public DeleteKeysAPDU(TPSBuffer keyVersion) {
        setCLA((byte) 0x84);
        setINS((byte) 0xE4);
        setP1((byte) 0x00);
        setP2((byte) 0x00);

        TPSBuffer keyData = new TPSBuffer();

        keyData.add((byte) 0xD2);               // tag for deleting key version
        keyData.add((byte) keyVersion.size());  // length of key version
        keyData.add(keyVersion);                // key version

        //CMS.debug("DeleteKeysAPDU: keyData = " + keyData.toHexString());
        
        setData(keyData);

    }

    @Override
    public APDU.Type getType() {
        return APDU.Type.APDU_DELETE_KEYS;

    }
}
