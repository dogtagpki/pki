package org.dogtagpki.tps.apdu;

import org.dogtagpki.tps.main.TPSBuffer;


public class ClearKeySlotsAPDU extends APDU {
    public ClearKeySlotsAPDU(byte[] slotList) {
        setCLA((byte) 0x84);
        setINS((byte) 0x55);
        setP1((byte) 0x0);
        setP2((byte) 0x0);

        data = new TPSBuffer();
        data.addBytes(slotList);

    }

    @Override
    public Type getType()
    {
        return Type.APDU_CLEAR_KEY_SLOTS;
    }

}
