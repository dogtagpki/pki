package org.dogtagpki.tps.apdu;

import org.dogtagpki.tps.main.TPSBuffer;

public class DeleteFileGP211APDU extends APDU {
    public DeleteFileGP211APDU(TPSBuffer aid) {
        trailer = new TPSBuffer();
        trailer.add((byte) 0x0);

        setCLA((byte) 0x84);
        setINS((byte) 0xE4);
        setP1((byte) 0x00);
        setP2((byte) 0x80);

        TPSBuffer AIDTLV = new TPSBuffer();

        AIDTLV.add((byte) 0x4f);
        AIDTLV.add((byte) aid.size());

        AIDTLV.add(aid);

        setData(AIDTLV);

    }

    public static void main(String[] args) {
        // TODO Auto-generated method stub

    }

}
